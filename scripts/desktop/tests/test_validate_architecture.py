import importlib.util
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).parents[1] / "validate_architecture.py"
SPEC = importlib.util.spec_from_file_location("validate_architecture", MODULE_PATH)
architecture = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(architecture)


class RustDependencyRulesTest(unittest.TestCase):
    def test_allows_documented_dependency_direction(self):
        violations = architecture.find_rust_dependency_violations(
            {
                "gocode-desktop": {"gocode-app-core", "gocode-platform-desktop"},
                "gocode-app-core": {"gocode-runtime-client", "gocode-local-store"},
                "gocode-platform-desktop": {"gocode-platform-ports"},
            }
        )

        self.assertEqual([], violations)

    def test_rejects_platform_implementation_importing_app_core(self):
        violations = architecture.find_rust_dependency_violations(
            {"gocode-platform-desktop": {"gocode-app-core"}}
        )

        self.assertEqual(
            ["gocode-platform-desktop -> gocode-app-core is forbidden"],
            violations,
        )

    def test_secure_store_allows_only_public_identity_and_acl_wrapper(self):
        allowed = architecture.find_rust_dependency_violations(
            {
                "gocode-secure-store": {
                    "gocode-api",
                    "gocode-macos-keychain-acl",
                }
            }
        )
        forbidden = architecture.find_rust_dependency_violations(
            {"gocode-secure-store": {"gocode-runtime"}}
        )

        self.assertEqual([], allowed)
        self.assertEqual(
            ["gocode-secure-store -> gocode-runtime is forbidden"],
            forbidden,
        )


class ProviderTerminalPersistenceBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def write(self, relative_path: str, source: str):
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")

    def test_rejects_raw_terminal_commit_request_outside_runtime_boundary(self):
        self.write(
            "crates/gocode-daemon/src/provider.rs",
            """
            use gocode_application::provider::ProviderTerminalCommitRequest;
            fn bypass(request: ProviderTerminalCommitRequest) {}
            """,
        )

        violations = architecture.find_provider_terminal_persistence_violations(
            self.root
        )

        self.assertEqual(
            [
                "crates/gocode-daemon/src/provider.rs accesses raw provider terminal "
                "persistence outside the runtime-owned boundary"
            ],
            violations,
        )

    def test_allows_application_store_and_runtime_persistence_implementation(self):
        source = "struct ProviderTerminalCommitRequest;"
        for relative_path in architecture.PROVIDER_TERMINAL_PERSISTENCE_ALLOWED:
            self.write(relative_path.as_posix(), source)

        violations = architecture.find_provider_terminal_persistence_violations(
            self.root
        )

        self.assertEqual([], violations)

    def test_rejects_application_alias_factory_bypass(self):
        self.write(
            "crates/gocode-application/src/provider/execution.rs",
            """
            use gocode_runtime::provider_execution::ProviderTerminalCommitRequest as Raw;
            pub fn bypass() -> Raw { unimplemented!() }
            """,
        )

        violations = architecture.find_provider_terminal_persistence_violations(
            self.root
        )

        self.assertEqual(
            [
                "crates/gocode-application/src/provider/execution.rs accesses raw "
                "provider terminal persistence outside the runtime-owned boundary"
            ],
            violations,
        )

    def test_rejects_terminal_test_support_on_production_dependency(self):
        packages = [
            {
                "name": "gocode-daemon",
                "dependencies": [
                    {
                        "name": "gocode-runtime",
                        "kind": None,
                        "features": ["provider-terminal-test-support"],
                    }
                ],
            }
        ]

        self.assertEqual(
            [
                "gocode-daemon enables provider-terminal-test-support outside "
                "dev-dependencies"
            ],
            architecture.find_provider_terminal_test_feature_violations(packages),
        )


class RendererConversationBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def write(self, relative_path: str, source: str):
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")

    def test_rejects_direct_runtime_and_replay_imports(self):
        self.write(
            "apps/desktop/src/pages/workspace/ui/WorkspacePage.vue",
            """
            <script setup lang="ts">
            import { ReplayCursor } from "@/shared/runtime-client/replay"
            </script>
            """,
        )

        violations = architecture.find_renderer_conversation_violations(self.root)

        self.assertEqual(
            [
                "apps/desktop/src/pages/workspace/ui/WorkspacePage.vue imports "
                "forbidden runtime/replay module @/shared/runtime-client/replay"
            ],
            violations,
        )

    def test_rejects_generic_tauri_emission_for_conversation_payloads(self):
        self.write(
            "apps/desktop/src/widgets/conversation-chat/model/live.ts",
            """
            import { emit } from "@tauri-apps/api/event"
            export const publishConversation = (payload: unknown) =>
              emit("conversation-update", payload)
            """,
        )

        violations = architecture.find_renderer_conversation_violations(self.root)

        self.assertEqual(
            [
                "apps/desktop/src/widgets/conversation-chat/model/live.ts emits "
                "Conversation payloads through generic Tauri events"
            ],
            violations,
        )

    def test_rejects_namespace_tauri_emission_for_conversation_payloads(self):
        self.write(
            "apps/desktop/src/widgets/conversation-chat/model/namespace-live.ts",
            """
            import * as events from "@tauri-apps/api/event"
            export const publishConversation = (payload: unknown) =>
              events.emit("conversation-update", payload)
            """,
        )

        violations = architecture.find_renderer_conversation_violations(self.root)

        self.assertEqual(
            [
                "apps/desktop/src/widgets/conversation-chat/model/namespace-live.ts "
                "emits Conversation payloads through generic Tauri events"
            ],
            violations,
        )

    def test_only_conversation_entity_api_may_construct_typed_channels(self):
        self.write(
            "apps/desktop/src/pages/workspace/model/live.ts",
            """
            import { Channel } from "@tauri-apps/api/core"
            export const onUpdate = new Channel()
            """,
        )
        self.write(
            "apps/desktop/src/entities/conversation/api/conversations.ts",
            """
            import { Channel } from "@tauri-apps/api/core"
            export const onUpdate = new Channel()
            """,
        )

        violations = architecture.find_renderer_conversation_violations(self.root)

        self.assertEqual(
            [
                "apps/desktop/src/pages/workspace/model/live.ts constructs a "
                "Conversation channel outside entities/conversation/api"
            ],
            violations,
        )

    def test_rejects_namespace_channel_construction_outside_entity_api(self):
        self.write(
            "apps/desktop/src/pages/workspace/model/namespace-live.ts",
            """
            import * as tauri from "@tauri-apps/api/core"
            export const onUpdate = new tauri.Channel()
            """,
        )

        violations = architecture.find_renderer_conversation_violations(self.root)

        self.assertEqual(
            [
                "apps/desktop/src/pages/workspace/model/namespace-live.ts constructs a "
                "Conversation channel outside entities/conversation/api"
            ],
            violations,
        )

    def test_rejects_default_and_dynamic_member_import_bypasses(self):
        self.write(
            "apps/desktop/src/widgets/conversation-chat/model/default-live.ts",
            """
            import events from "@tauri-apps/api/event"
            export const publishConversation = (payload: unknown) =>
              events.emit("conversation-update", payload)
            """,
        )
        self.write(
            "apps/desktop/src/widgets/conversation-chat/model/dynamic-live.ts",
            """
            export async function publishConversation(payload: unknown) {
              const events = await import("@tauri-apps/api/event")
              await events.emit("conversation-update", payload)
            }
            """,
        )
        self.write(
            "apps/desktop/src/pages/workspace/model/default-channel.ts",
            """
            import tauri from "@tauri-apps/api/core"
            export const onUpdate = new tauri.Channel()
            """,
        )
        self.write(
            "apps/desktop/src/pages/workspace/model/dynamic-channel.ts",
            """
            export async function createChannel() {
              const tauri = await import("@tauri-apps/api/core")
              return new tauri.Channel()
            }
            """,
        )

        violations = architecture.find_renderer_conversation_violations(self.root)

        self.assertEqual(
            [
                "apps/desktop/src/pages/workspace/model/default-channel.ts constructs a "
                "Conversation channel outside entities/conversation/api",
                "apps/desktop/src/pages/workspace/model/dynamic-channel.ts constructs a "
                "Conversation channel outside entities/conversation/api",
                "apps/desktop/src/widgets/conversation-chat/model/default-live.ts emits "
                "Conversation payloads through generic Tauri events",
                "apps/desktop/src/widgets/conversation-chat/model/dynamic-live.ts emits "
                "Conversation payloads through generic Tauri events",
            ],
            violations,
        )

    def test_rejects_optional_dot_and_bracket_member_bypasses(self):
        self.write(
            "apps/desktop/src/widgets/conversation-chat/model/optional-dot.ts",
            """
            import * as events from "@tauri-apps/api/event"
            export const publishConversation = (payload: unknown) =>
              events?.emit?.("conversation-update", payload)
            """,
        )
        self.write(
            "apps/desktop/src/widgets/conversation-chat/model/optional-bracket.ts",
            """
            import events from "@tauri-apps/api/event"
            export const publishConversation = (payload: unknown) =>
              events?.["emit"]("conversation-update", payload)
            """,
        )
        self.write(
            "apps/desktop/src/widgets/conversation-chat/model/optional-dynamic.ts",
            """
            export async function publishConversation(payload: unknown) {
              const events = await import("@tauri-apps/api/event")
              await events?.emit("conversation-update", payload)
            }
            """,
        )
        self.write(
            "apps/desktop/src/widgets/conversation-chat/model/optional-direct-dynamic.ts",
            """
            export async function publishConversation(payload: unknown) {
              await (await import("@tauri-apps/api/event"))?.emit?.(
                "conversation-update",
                payload,
              )
            }
            """,
        )
        self.write(
            "apps/desktop/src/pages/workspace/model/optional-dot-channel.ts",
            """
            import * as tauri from "@tauri-apps/api/core"
            export const onUpdate = new (tauri?.Channel)()
            """,
        )
        self.write(
            "apps/desktop/src/pages/workspace/model/optional-bracket-channel.ts",
            """
            import tauri from "@tauri-apps/api/core"
            export const onUpdate = new (tauri?.["Channel"])()
            """,
        )
        self.write(
            "apps/desktop/src/pages/workspace/model/optional-dynamic-channel.ts",
            """
            export async function createChannel() {
              const tauri = await import("@tauri-apps/api/core")
              return new (tauri?.Channel)()
            }
            """,
        )
        self.write(
            "apps/desktop/src/pages/workspace/model/optional-direct-dynamic-channel.ts",
            """
            export async function createChannel() {
              return new ((await import("@tauri-apps/api/core"))?.Channel)()
            }
            """,
        )

        violations = architecture.find_renderer_conversation_violations(self.root)

        self.assertEqual(
            [
                "apps/desktop/src/pages/workspace/model/optional-bracket-channel.ts "
                "constructs a Conversation channel outside entities/conversation/api",
                "apps/desktop/src/pages/workspace/model/optional-direct-dynamic-channel.ts "
                "constructs a Conversation channel outside entities/conversation/api",
                "apps/desktop/src/pages/workspace/model/optional-dot-channel.ts constructs "
                "a Conversation channel outside entities/conversation/api",
                "apps/desktop/src/pages/workspace/model/optional-dynamic-channel.ts "
                "constructs a Conversation channel outside entities/conversation/api",
                "apps/desktop/src/widgets/conversation-chat/model/optional-bracket.ts emits "
                "Conversation payloads through generic Tauri events",
                "apps/desktop/src/widgets/conversation-chat/model/optional-direct-dynamic.ts "
                "emits Conversation payloads through generic Tauri events",
                "apps/desktop/src/widgets/conversation-chat/model/optional-dot.ts emits "
                "Conversation payloads through generic Tauri events",
                "apps/desktop/src/widgets/conversation-chat/model/optional-dynamic.ts emits "
                "Conversation payloads through generic Tauri events",
            ],
            violations,
        )


if __name__ == "__main__":
    unittest.main()
