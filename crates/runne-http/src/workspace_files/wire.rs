use runne_api::{WorkspaceFileContent, WorkspaceFileKind, WorkspaceFilePage};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FileEntryWire {
    path: String,
    kind: &'static str,
    size_bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FilePageWire {
    items: Vec<FileEntryWire>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FileContentWire {
    path: String,
    content: String,
    size_bytes: u64,
}

impl From<WorkspaceFilePage> for FilePageWire {
    fn from(value: WorkspaceFilePage) -> Self {
        Self {
            items: value
                .items()
                .iter()
                .map(|item| FileEntryWire {
                    path: item.relative_path().into(),
                    kind: match item.kind() {
                        WorkspaceFileKind::File => "file",
                        WorkspaceFileKind::Directory => "directory",
                    },
                    size_bytes: item.size_bytes(),
                })
                .collect(),
        }
    }
}

impl From<WorkspaceFileContent> for FileContentWire {
    fn from(value: WorkspaceFileContent) -> Self {
        Self {
            path: value.relative_path().into(),
            content: value.content().into(),
            size_bytes: value.size_bytes(),
        }
    }
}
