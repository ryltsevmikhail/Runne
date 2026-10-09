pub(super) fn python_literal(value: &str) -> String {
    serde_json::to_string(value).expect("encode fixture path as a Python string literal")
}

pub(super) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub(super) const PYTHON_MATRIX: &str = r#"
import errno
import os
import pathlib
import sys

workspace = pathlib.Path(@@WORKSPACE@@)
sibling = pathlib.Path(@@SIBLING@@)
symlink_target = pathlib.Path(@@SYMLINK_TARGET@@)
symlink_path = pathlib.Path(@@SYMLINK@@)
hardlink_source = pathlib.Path(@@HARDLINK_SOURCE@@)
hardlink_alias = pathlib.Path(@@HARDLINK_ALIAS@@)
rename_source = pathlib.Path(@@RENAME_SOURCE@@)
rename_target = pathlib.Path(@@RENAME_TARGET@@)
replace_source = pathlib.Path(@@REPLACE_SOURCE@@)
replace_target = pathlib.Path(@@REPLACE_TARGET@@)
case_upper = pathlib.Path(@@CASE_UPPER@@)
case_lower = pathlib.Path(@@CASE_LOWER@@)
case_log = pathlib.Path(@@CASE_LOG@@)
child_marker = pathlib.Path(@@CHILD_MARKER@@)
hidden_device_source = pathlib.Path(@@HIDDEN_DEVICE_SOURCE@@)
cross_source = pathlib.Path(@@CROSS_SOURCE@@)
cross_output = pathlib.Path(@@CROSS_OUTPUT@@)
cross_link_target = pathlib.Path(@@CROSS_LINK_TARGET@@)
cross_rename_target = pathlib.Path(@@CROSS_RENAME_TARGET@@)
fixture_cwd = pathlib.Path(@@FIXTURE_CWD@@)

workspace_device = os.stat(workspace).st_dev
assert os.stat(sibling).st_dev == workspace_device
os.symlink(symlink_target, symlink_path)
with symlink_path.open("a", encoding="utf-8") as target:
    target.write("symlink-followed\n")

os.link(hardlink_source, hardlink_alias)
source_stat = os.stat(hardlink_source)
alias_stat = os.stat(hardlink_alias)
assert (source_stat.st_dev, source_stat.st_ino) == (alias_stat.st_dev, alias_stat.st_ino)
with hardlink_alias.open("a", encoding="utf-8") as target:
    target.write("hardlink-followed\n")

assert os.stat(rename_source).st_dev == os.stat(rename_target.parent).st_dev
os.rename(rename_source, rename_target)
assert replace_target.read_text(encoding="utf-8") == "replacement-old\n"
os.replace(replace_source, replace_target)

case_upper.write_text("upper\n", encoding="utf-8")
case_lower.write_text("lower\n", encoding="utf-8")
same_case_file = os.path.samefile(case_upper, case_lower)
if same_case_file:
    assert case_upper.read_text(encoding="utf-8") == "lower\n"
    assert case_lower.read_text(encoding="utf-8") == "lower\n"
else:
    assert case_upper.read_text(encoding="utf-8") == "upper\n"
    assert case_lower.read_text(encoding="utf-8") == "lower\n"
case_log.write_text("case_sensitive=" + str(not same_case_file).lower() + "\n", encoding="utf-8")

try:
    hidden_device_source.stat()
except FileNotFoundError:
    pass
else:
    raise AssertionError("the host /dev/shm canary is visible inside the child namespace")

cross_device = os.stat(cross_source).st_dev
assert cross_device != workspace_device, "cross-volume fixture requires distinct st_dev"
cross_contents = cross_source.read_text(encoding="utf-8")
assert cross_contents == "cross-volume-input\n"
cross_output.write_text("cross-volume-output:" + cross_contents, encoding="utf-8")
try:
    os.link(cross_source, cross_link_target)
except OSError as error:
    assert error.errno == errno.EXDEV, "cross-volume hard link failed with errno " + str(error.errno)
else:
    raise AssertionError("cross-volume hard link unexpectedly succeeded")
try:
    os.rename(cross_source, cross_rename_target)
except OSError as error:
    assert error.errno == errno.EXDEV, "cross-volume rename failed with errno " + str(error.errno)
else:
    raise AssertionError("cross-volume rename unexpectedly succeeded")
assert cross_source.exists()

expected_arguments = ["argument with spaces", "value with 'single' and \"double\" quotes"]
assert sys.argv[1:] == expected_arguments, "structured argv was changed by the shell"
assert os.environ["RUNNE_TEST_PATH_MATRIX_ONLY"] == "fixture-only value with 'quotes'"
assert os.path.samefile(pathlib.Path.cwd(), fixture_cwd), "child did not inherit the fixture cwd"
marker = (
    "argv0=" + sys.argv[1]
    + ";argv1=" + sys.argv[2]
    + ";env=" + os.environ["RUNNE_TEST_PATH_MATRIX_ONLY"]
    + ";cwd=" + pathlib.Path.cwd().name
    + "\n"
)
with child_marker.open("a", encoding="utf-8") as output:
    output.write(marker)
"#;
