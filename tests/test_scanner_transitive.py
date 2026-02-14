"""Tests for _has_transitive_openssl tree traversal logic."""

import pytest
from openssl_scanner.dependency_resolver import DependencyNode
from openssl_scanner.scanner import Scanner


class TestHasTransitiveOpenSSL:
    """
    Test tree:
        app (root)
          +-- libfoo.so
          |     +-- libcrypto.so.3  (is_openssl_lib=True)
          +-- libbar.so
          |     +-- libutil.so
          +-- libbaz.so
                +-- libqux.so
                      +-- libssl.so.3  (is_openssl_lib=True)
    """

    def setup_method(self):
        self.scanner = Scanner()

        self.libcrypto = DependencyNode(
            name="libcrypto.so.3",
            path="/usr/lib/libcrypto.so.3",
            is_openssl_lib=True,
        )
        self.libfoo = DependencyNode(
            name="libfoo.so",
            path="/usr/lib/libfoo.so",
            children=[self.libcrypto],
        )

        self.libutil = DependencyNode(
            name="libutil.so",
            path="/usr/lib/libutil.so",
        )
        self.libbar = DependencyNode(
            name="libbar.so",
            path="/usr/lib/libbar.so",
            children=[self.libutil],
        )

        self.libssl = DependencyNode(
            name="libssl.so.3",
            path="/usr/lib/libssl.so.3",
            is_openssl_lib=True,
        )
        self.libqux = DependencyNode(
            name="libqux.so",
            path="/usr/lib/libqux.so",
            children=[self.libssl],
        )
        self.libbaz = DependencyNode(
            name="libbaz.so",
            path="/usr/lib/libbaz.so",
            children=[self.libqux],
        )

        self.root = DependencyNode(
            name="app",
            path="/usr/bin/app",
            children=[self.libfoo, self.libbar, self.libbaz],
        )

        self.openssl_paths = self.scanner._find_openssl_paths(self.root)

    def test_direct_child_openssl(self):
        """libfoo has libcrypto as direct child -> True."""
        assert self.scanner._has_transitive_openssl(
            "/usr/lib/libfoo.so", self.openssl_paths, self.root
        )

    def test_no_openssl_in_subtree(self):
        """libbar has only libutil, no OpenSSL -> False."""
        assert not self.scanner._has_transitive_openssl(
            "/usr/lib/libbar.so", self.openssl_paths, self.root
        )

    def test_grandchild_openssl(self):
        """libbaz -> libqux -> libssl, transitive OpenSSL -> True."""
        assert self.scanner._has_transitive_openssl(
            "/usr/lib/libbaz.so", self.openssl_paths, self.root
        )

    def test_not_in_tree(self):
        """Path not present in tree -> False."""
        assert not self.scanner._has_transitive_openssl(
            "/usr/lib/libnothere.so", self.openssl_paths, self.root
        )

    def test_openssl_node_itself(self):
        """The OpenSSL node itself has no OpenSSL *children* -> False."""
        assert not self.scanner._has_transitive_openssl(
            "/usr/lib/libcrypto.so.3", self.openssl_paths, self.root
        )

    def test_leaf_node_no_children(self):
        """libutil is a leaf with no children -> False."""
        assert not self.scanner._has_transitive_openssl(
            "/usr/lib/libutil.so", self.openssl_paths, self.root
        )

    def test_root_has_transitive(self):
        """Root app has OpenSSL in its subtree -> True."""
        assert self.scanner._has_transitive_openssl(
            "/usr/bin/app", self.openssl_paths, self.root
        )

    def test_empty_openssl_paths(self):
        """No OpenSSL in tree at all -> always False."""
        assert not self.scanner._has_transitive_openssl(
            "/usr/lib/libfoo.so", set(), self.root
        )

    def test_find_openssl_paths_correctness(self):
        """Verify _find_openssl_paths collects both OpenSSL libs."""
        assert self.openssl_paths == {
            "/usr/lib/libcrypto.so.3",
            "/usr/lib/libssl.so.3",
        }

    def test_find_openssl_paths_skips_none_path(self):
        """is_openssl_lib=True but path=None should NOT be collected."""
        broken = DependencyNode(
            name="libcrypto.so", path=None, is_openssl_lib=True,
        )
        root = DependencyNode(name="app", path="/app", children=[broken])
        paths = self.scanner._find_openssl_paths(root)
        assert paths == set()

    def test_node_with_none_path(self):
        """Node with path=None (unresolved library) should not match."""
        unresolved = DependencyNode(name="libmissing.so", path=None)
        root = DependencyNode(
            name="app", path="/usr/bin/app",
            children=[unresolved],
        )
        openssl_paths = self.scanner._find_openssl_paths(root)
        assert openssl_paths == set()
        assert not self.scanner._has_transitive_openssl(
            "/usr/bin/app", openssl_paths, root
        )

    def test_empty_tree_root_only(self):
        """Single root node, no children, not OpenSSL -> False."""
        root = DependencyNode(name="app", path="/usr/bin/app")
        paths = self.scanner._find_openssl_paths(root)
        assert paths == set()
        assert not self.scanner._has_transitive_openssl(
            "/usr/bin/app", paths, root
        )

    def test_diamond_dependency_dedup(self):
        """Same OpenSSL lib as child of two parents -> collected once."""
        crypto1 = DependencyNode(
            name="libcrypto.so.3", path="/usr/lib/libcrypto.so.3",
            is_openssl_lib=True,
        )
        crypto2 = DependencyNode(
            name="libcrypto.so.3", path="/usr/lib/libcrypto.so.3",
            is_openssl_lib=True,
        )
        libfoo = DependencyNode(
            name="libfoo.so", path="/lib/libfoo.so", children=[crypto1],
        )
        libbar = DependencyNode(
            name="libbar.so", path="/lib/libbar.so", children=[crypto2],
        )
        root = DependencyNode(name="app", path="/app", children=[libfoo, libbar])
        paths = self.scanner._find_openssl_paths(root)
        assert paths == {"/usr/lib/libcrypto.so.3"}
        assert self.scanner._has_transitive_openssl("/lib/libfoo.so", paths, root)
        assert self.scanner._has_transitive_openssl("/lib/libbar.so", paths, root)

    def test_find_openssl_paths_root_is_openssl(self):
        """Root node itself is OpenSSL -> its path is in the result."""
        root = DependencyNode(
            name="libcrypto.so", path="/lib/libcrypto.so",
            is_openssl_lib=True,
        )
        paths = self.scanner._find_openssl_paths(root)
        assert paths == {"/lib/libcrypto.so"}

    def test_openssl_direct_and_grandchild(self):
        """OpenSSL as direct child AND also deeper in the same subtree."""
        deep_ssl = DependencyNode(
            name="libssl.so", path="/lib/libssl.so", is_openssl_lib=True,
        )
        middle = DependencyNode(
            name="libmid.so", path="/lib/libmid.so", children=[deep_ssl],
        )
        crypto = DependencyNode(
            name="libcrypto.so", path="/lib/libcrypto.so",
            is_openssl_lib=True,
        )
        parent = DependencyNode(
            name="libparent.so", path="/lib/libparent.so",
            children=[crypto, middle],
        )
        root = DependencyNode(name="app", path="/app", children=[parent])
        paths = self.scanner._find_openssl_paths(root)
        assert paths == {"/lib/libcrypto.so", "/lib/libssl.so"}
        assert self.scanner._has_transitive_openssl(
            "/lib/libparent.so", paths, root
        )
