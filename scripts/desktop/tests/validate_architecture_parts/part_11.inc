def _test_oauth_codec_edge_is_explicit_and_shape_bound(self):
    dependency = {
        "name": "runne-provider-oauth",
        "kind": None,
        "target": None,
        "rename": None,
        "optional": False,
        "path": "/repo/crates/runne-provider-oauth",
    }
    self.assertEqual(
        [],
        architecture.find_oauth_codec_dependency_violations([
            {"name": "runne-secure-store", "dependencies": [dependency]},
            {"name": "runne-daemon-responses-effect", "dependencies": [dependency]},
        ]),
    )
    for mutation in (
        {"name": "runne-daemon", "dependencies": [dependency]},
        {"name": "runne-secure-store", "dependencies": [{**dependency, "optional": True}]},
        {"name": "runne-secure-store", "dependencies": [{**dependency, "target": "cfg(unix)"}]},
        {"name": "runne-secure-store", "dependencies": [{**dependency, "path": "/external/oauth"}]},
    ):
        with self.subTest(mutation=mutation):
            self.assertEqual(
                [f"{mutation['name']} -> runne-provider-oauth has forbidden dependency shape"],
                architecture.find_oauth_codec_dependency_violations([mutation]),
            )


RustDependencyRulesTest.test_oauth_codec_edge_is_explicit_and_shape_bound = (
    _test_oauth_codec_edge_is_explicit_and_shape_bound
)
