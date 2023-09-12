"""Implementation of a Treaccp which is an interface that connects the elements with the pseudorandom treap."""

from treaccp.nodes import to_key, build_treap
from treaccp.acc import Acc


class ErrNoRootNode(Exception):
    """Treaccp has no root node."""

    pass


class Treaccp:
    """Persistent accumulator tree. This is mostly an interface wrapper around elements and nodes."""

    def __init__(self, root, elements):
        assert isinstance(elements, set)
        self.root = root
        self.elements = elements

    @property
    def merkle_root(self):
        return self.root.merkle_root if self.root else None

    def to_acc(self):
        if not self.root:
            raise ErrNoRootNode
        return Acc(self.root)

    def prove_inclusion(self, el):
        key = to_key(el)
        return self.root.prove_inclusion(key)

    def verify_inclusion(self, el, proof):
        key = to_key(el)
        return self.root.verify_inclusion(key, proof)

    def verify_inclusions(self, els, proof):
        keys = [to_key(el) for el in els]
        return self.root.verify_inclusions(keys, proof)

    def prove_exclusion(self, el):
        key = to_key(el)
        return self.root.prove_exclusion(key)

    def verify_exclusion(self, el, proof):
        key = to_key(el)
        return self.root.verify_exclusion(key, proof)

    def verify_exclusions(self, els, proof):
        keys = [to_key(el) for el in els]
        return self.root.verify_exclusions(keys, proof)

    def insert_proof(self, el):
        key = to_key(el)
        return self.root.insert_proof(key)

    def remove_proof(self, el):
        key = to_key(el)
        return self.root.remove_proof(key)

    def find(self, el):
        key = to_key(el)
        return self.root.find(key)

    def insert(self, el, prove=True):
        return self.insert_many([el], prove=prove)

    def insert_many(self, els, prove=True):
        keys = [to_key(el) for el in els]
        new_root, proof = self.root.insert_many(keys, prove=prove)
        new_elements = self.elements | set(els)

        return Treaccp(new_root, new_elements), proof

    def remove(self, el, prove=True):
        return self.remove_many([el], prove=prove)

    def remove_many(self, els, prove=True):
        keys = [to_key(el) for el in els]
        new_root, proof = self.root.remove_many(keys, prove=prove)
        new_elements = self.elements - set(els)

        return Treaccp(new_root, new_elements), proof

    def is_member(self, el):
        return el in self.elements

    def is_not_member(self, el):
        return not self.is_member(el)


def build_treaccp(elements):
    root = build_treap(elements)
    return Treaccp(root, set(elements))
