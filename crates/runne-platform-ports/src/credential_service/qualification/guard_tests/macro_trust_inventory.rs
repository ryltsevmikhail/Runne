use syn::visit::{self, Visit};

pub(super) fn production_items(file: &syn::File) -> Vec<&syn::Item> {
    struct Items<'ast>(Vec<&'ast syn::Item>);

    impl<'ast> Visit<'ast> for Items<'ast> {
        fn visit_item(&mut self, item: &'ast syn::Item) {
            if super::super::item_is_test_only(super::super::item_attrs(item)) {
                return;
            }
            self.0.push(item);
            visit::visit_item(self, item);
        }

        fn visit_stmt(&mut self, statement: &'ast syn::Stmt) {
            if super::super::syntax::stmt_is_test_only(statement) {
                return;
            }
            visit::visit_stmt(self, statement);
        }
    }

    let mut items = Items(Vec::new());
    items.visit_file(file);
    items.0
}
