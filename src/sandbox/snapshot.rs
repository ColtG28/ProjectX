use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SnapshotStrategy {
    ContainerLayerCommit,
    VmSnapshot,
    FilesystemOverlay,
}

impl SnapshotStrategy {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ContainerLayerCommit => "container-layer-commit",
            Self::VmSnapshot => "vm-snapshot",
            Self::FilesystemOverlay => "filesystem-overlay",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotState {
    pub strategy: SnapshotStrategy,
    pub snapshot_id: String,
    pub revert_command: String,
    pub create_command: String,
}

pub fn build_snapshot_state(
    strategy: SnapshotStrategy,
    snapshot_id: impl Into<String>,
) -> SnapshotState {
    let snapshot_id = snapshot_id.into();
    let (create_command, revert_command) = match strategy {
        SnapshotStrategy::ContainerLayerCommit => (
            format!("docker commit <container> {}", snapshot_id),
            format!("docker image rm {}", snapshot_id),
        ),
        SnapshotStrategy::VmSnapshot => (
            format!("VBoxManage snapshot <vm> take {}", snapshot_id),
            format!("VBoxManage snapshot <vm> restore {}", snapshot_id),
        ),
        SnapshotStrategy::FilesystemOverlay => (
            format!("mount-overlay {}", snapshot_id),
            format!("umount-overlay {}", snapshot_id),
        ),
    };
    SnapshotState {
        strategy,
        snapshot_id,
        revert_command,
        create_command,
    }
}

#[cfg(test)]
mod tests {
    use super::{build_snapshot_state, SnapshotStrategy};

    #[test]
    fn builds_revert_command() {
        let state = build_snapshot_state(SnapshotStrategy::FilesystemOverlay, "overlay-1");
        assert!(state.revert_command.contains("overlay-1"));
    }
}
