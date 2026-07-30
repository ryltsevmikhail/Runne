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


if __name__ == "__main__":
    unittest.main()
