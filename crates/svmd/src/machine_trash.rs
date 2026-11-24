use super::*;
use svm_core::library::TrashEntry;

fn restore_receipt(entry:&TrashEntry)->Result<RemovalReceipt,ApiError> {
    if !fs::symlink_metadata(entry.path.join("backup-publishing.json")).is_err_and(|e|e.kind()==io::ErrorKind::NotFound) {
        return Err(refused("This restore was incomplete. Retry from the original backup snapshot."));
    }
    let mut marker=entry.path.join("removal-complete.json");
    if entry.restoring && !marker.try_exists().map_err(io_error)? {marker=entry.path.join("last-restored-removal.json");}
    let checked=marker.canonicalize().map_err(|_|refused("This bundle has no verified removal receipt. Its files are available in the trash folder."))?;
    if checked!=marker || !checked.is_file() {return Err(refused("The removal receipt is linked or invalid."));}
    let receipt:RemovalReceipt=svm_core::read_json(&marker).map_err(|_|refused("The removal receipt is unreadable."))?;
    if receipt.id!=entry.machine.id || receipt.bytes.is_some()!=receipt.retained.is_some() {
        return Err(refused("The removal receipt does not match this machine."));
    }
    // QEMU checkpoints are stored inside the bundle’s qcow2 disk.
    let needs_checkpoint_export = entry.machine.engine == EngineKind::HyperV && entry.machine.snaps > 0;
    if let Some(rel)=receipt.retained.as_deref() {
        if !rel.strip_prefix("retained/").is_some_and(id_ok) || receipt.bytes==Some(0) {return Err(refused("The retained export location is invalid."));}
        let archive=entry.path.join(rel);
        if archive.canonicalize().ok().as_ref()!=Some(&archive) || !archive.is_dir() {return Err(refused("The retained export is missing or linked."));}
    } else if entry.machine.state!=VmState::Off || entry.machine.tpm==Some(true) || needs_checkpoint_export {
        return Err(refused("This guest requires a retained export of its saved state, TPM or checkpoints."));
    }
    Ok(receipt)
}

impl Machines {
    pub(super) fn trash_list(&self)->Result<Reply,ApiError>{
        let rows=self.library.list_trash().map_err(store)?.into_iter().map(|e|{
            let receipt=restore_receipt(&e);
            let reason=if e.purging {Some("Permanent deletion has already started.".to_owned())}
                else if e.machine.engine!=EngineKind::HyperV {Some("Restoring a discarded machine is unavailable for this engine.".to_owned())}
                else if e.machine.template.is_some() || e.machine.linked_from.is_some() {Some("Restoring a deleted template or linked clone is unavailable.".to_owned())}
                else {receipt.as_ref().err().map(|error|error.message.clone())};
            json!({"key":e.key,"name":e.machine.name,"id":e.machine.id,"os":e.machine.os,
                "restoring":e.restoring,"purging":e.purging,"restoreReason":reason,
                "retainedBytes":receipt.ok().and_then(|r|r.bytes)})
        }).collect::<Vec<_>>();
        Ok(Reply::json(json!(rows)))
    }

    fn selected_trash(&self,key:&str)->Result<TrashEntry,ApiError> {
        self.library.list_trash().map_err(store)?.into_iter().find(|entry|entry.key==key)
            .ok_or_else(||ApiError::new(404,"not_found","This trash entry is no longer available."))
    }

    pub(super) fn restore_trash(&mut self,key:&str,networks:&[Network],events:&mut Events)->Result<Reply,ApiError> {
        let task = self.prepare_restore(key, networks)?;
        task.run(&mut *self.engine)(self, networks, events)
    }

    pub(super) fn prepare_restore(&mut self,key:&str,networks:&[Network])->Result<MachineTask,ApiError> {
        let before=self.selected_trash(key)?;
        if before.machine.template.is_some() || before.machine.linked_from.is_some() {
            return Err(refused("Restoring a deleted template or linked clone is unavailable."));
        }
        if before.machine.engine!=EngineKind::HyperV {return Err(refused("Restoring a discarded machine is unavailable for this engine."));}
        let receipt=restore_receipt(&before)?;
        if before.purging {return Err(refused("Permanent deletion has already started."));}
        let net=network(networks,&before.machine.net)?;
        if net.mode!=NetworkMode::Nat && (!net.subnet.usable(before.machine.ip) || net.gateway==Some(before.machine.ip)) {
            return Err(refused("The original guest address no longer belongs to its network. Restore its original network settings first."));
        }
        if !id_ok(&before.machine.id) {return Err(bad("Invalid machine ID in trash."));}
        if !before.restoring {self.engine.trash_detached(&before.machine.id,&before.path).map_err(engine)?;}
        let entry=self.library.prepare_restore(key).map_err(store)?;
        self.engine.register(&entry.machine.id,&entry.path).map_err(engine)?;
        let key=key.to_owned();
        Ok(MachineTask::new(vec![entry.machine.id.clone()], None, move |driver| {
            let mut vm=entry.machine;
            let attempt=(|| -> Result<(),ApiError> {
                driver.register(&vm.id,&entry.path).map_err(engine)?;
                if !driver.restored_registration(&vm.id).map_err(engine)? {
                    if let Some(rel)=receipt.retained.as_deref() {
                        driver.import_retained(&vm,&entry.path,rel).map_err(engine)?;
                    } else {
                        // Define must attach the installed disk rather than allocate an empty one.
                        let mut definition=vm.clone();
                        if definition.disk_path.is_some() || definition.disk_gb.is_some() {
                            let rel=definition.disk_path.as_deref().unwrap_or_else(||Path::new("system.vhdx"));
                            let disk=checked_media(&entry.path.join(rel),"vhdx")?;
                            if !disk.starts_with(&entry.path) {return Err(refused("The original disk is outside this bundle."));}
                            definition.disk_path=Some(disk);definition.disk_gb=None;
                        }
                        driver.define(&definition).map_err(engine)?;
                    }
                }
                if !driver.restored_registration(&vm.id).map_err(engine)? {return Err(refused("The engine could not verify the restored machine."));}
                if receipt.retained.is_none() {
                    let boot=entry.path.join("boot-order.json");
                    if boot.try_exists().map_err(io_error)? {
                        let order:String=svm_core::read_json(&boot).map_err(store)?;
                        if !matches!(order.as_str(),"disk"|"image") {return Err(refused("The recorded boot order is invalid."));}
                        driver.change_storage(&vm,"bootFirst",&json!(order)).map_err(engine)?;
                    }
                }
                vm.state=driver.state(&vm.id).map_err(engine)?;
                if active(vm.state) {return Err(refused("The restored machine was unexpectedly running. Verify it in Hyper-V before continuing."));}
                vm.cores.clear();
                vm.snaps=u32::try_from(driver.list_snapshots(&vm.id).map_err(engine)?.len()).map_err(|_|refused("Too many checkpoints."))?;
                Ok(())
            })();
            Box::new(move |machines, networks, events| {
                let published = attempt.and_then(|()| {
                    svm_core::write_json(&entry.path.join("vm.json"),&vm).map_err(store)?;
                    machines.library.finish_restore(&key).map_err(store)
                });
                if let Err(error)=published {
                    // Only move the files back when the engine can prove nothing refers to them.
                    if machines.engine.trash_detached(&vm.id,&entry.path).is_ok() {
                        machines.library.cancel_restore(&key).map_err(store)?;
                    }
                    return Err(error);
                }
                machines.inventory.push(vm.clone());
                machines.unavailable.remove(&vm.id);
                machines.uncertain.remove(&vm.id);
                events.record("restored",&format!("{} was restored from library trash.",vm.id))?;
                Ok(Reply::json(machines.published(&vm,networks)))
            })
        }))
    }

    pub(super) fn delete_trash(&mut self,key:&str,body:&Value,events:&mut Events)->Result<Reply,ApiError> {
        let entry = self.selected_trash(key)?;
        let expected = || format!("Permanent deletion requires confirmName to equal \"{}\".", entry.machine.name);
        let name = body.get("confirmName").and_then(Value::as_str).ok_or_else(|| bad(expected()))?;
        if body.as_object().is_some_and(|fields| fields.len() != 1) {
            return Err(bad("Permanent deletion accepts only the confirmName field."));
        }
        if name != entry.machine.name { return Err(refused(expected())); }
        if entry.machine.template.is_some() { self.require_no_linked_clones(&entry.machine.id)?; }
        if !entry.metadata_only {
            // A purge that already started passed this check before it wrote its own record, so a
            // purge stopped after it removed the receipt can still be finished.
            if entry.machine.engine==EngineKind::Qemu && !entry.purging {restore_receipt(&entry)?;}
            self.driver_mut(entry.machine.engine)?.trash_detached(&entry.machine.id,&entry.path).map_err(engine)?;
        }
        if entry.restoring {self.library.cancel_restore(key).map_err(store)?;}
        self.library.purge_trash(key,name).map_err(|error| {
            let _ = events.record("trash delete failed", &format!("{}: {error:?}", entry.machine.id));
            store(error)
        })?;
        events.record("trash deleted",&format!("The trashed bundle for {} was permanently deleted.",entry.machine.id))?;
        Ok(Reply::json(json!({"deleted":true})))
    }
}
