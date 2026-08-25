// Parent-side protected named-pipe transport for bundled `runned.exe`.

use runne_windows_native_handle::ProtectedNamedPipeChannel;

type WindowsChildChannel = ProtectedNamedPipeChannel;

fn create_windows_channel() -> Result<WindowsChildChannel, ProtectedBundledRuntimeError> {
    ProtectedNamedPipeChannel::create()
        .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)
}
