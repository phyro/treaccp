"""Implementations of an accumulator for our Treaccp structure."""

from treaccp.nodes import insert, remove, to_key, is_treap, ErrMerkleRootMismatch


class Acc:
    """Accumulator that holds only a merkle root."""

    def __init__(self, node):
        self.merkle_root = node.merkle_root

    def verify_inclusion(self, el, proof):
        """Verifies an element is included in the set."""
        return self.verify_inclusions([el], proof)

    def verify_inclusions(self, els, proof):
        """Verifies multiple elements are included in the set."""
        # We only verify that merkle root is the same. The delegated call to Treap.verify_inclusions will compute
        # merkle root and catch any incorrect values.
        if self.merkle_root != proof.merkle_root:
            raise ErrMerkleRootMismatch(
                f"Expected: {self.merkle_root}, got: {proof.merkle_root}"
            )
        keys = [to_key(el) for el in els]
        return proof.verify_inclusions(keys, proof)

    def verify_exclusion(self, el, proof):
        """Verifies an element is not included in the set."""
        return self.verify_exclusions([el], proof)

    def verify_exclusions(self, els, proof):
        """Verifies multiple elements are not included in the set."""
        # We only verify that merkle root is the same. The delegated call to Treap.verify_inclusions will compute
        # merkle root and catch any incorrect values.
        if self.merkle_root != proof.merkle_root:
            raise ErrMerkleRootMismatch(
                f"Expected: {self.merkle_root}, got: {proof.merkle_root}"
            )
        keys = [to_key(el) for el in els]
        return proof.verify_exclusions(keys, proof)

    def insert(self, el, proof):
        """Inserts a key into accumulator. It needs a compressed tree that has enough information to insert the
        element without touching any of the compressed nodes. Returns a new accumulator and updated compressed tree.
        """
        return self.insert_many([el], proof)

    def insert_many(self, els, proof):
        """Inserts many elements in the accumulator with a single merkle root verification."""

        # Verify the compressed tree is the same as the tree we have
        proof_root = proof.compute_merkle_root()
        if self.merkle_root != proof_root:
            raise ErrMerkleRootMismatch(
                f"Expected: {self.merkle_root}, got: {proof_root}"
            )

        compressed_tree = proof
        for el in els:
            key = to_key(el)
            compressed_tree = insert(compressed_tree, key)

        return Acc(compressed_tree), compressed_tree

    def remove(self, el, proof):
        """Removes the element from the accumulator. Like insert, it needs a compressed tree with enough information
        and returns the new accumulator and compressed proof."""
        return self.remove_many([el], proof)

    def remove_many(self, els, proof):
        """Removes many elements from the accumulator with a single merkle root verification."""

        # Verify the compressed tree is the same as the tree we have
        proof_root = proof.compute_merkle_root()
        if self.merkle_root != proof_root:
            raise ErrMerkleRootMismatch(
                f"Expected: {self.merkle_root}, got: {proof_root}"
            )

        compressed_tree = proof
        for el in els:
            key = to_key(el)
            compressed_tree = remove(compressed_tree, key)

        return Acc(compressed_tree), compressed_tree

    # NOTE: The whole warp idea is still being thought through, but it seems like something worth researching
    def warp(self, proof, added, removed, new_proof):
        """
        Warps from state 'proof' to new state 'new_proof'.
        
        We use the fact that there's only one valid treap with these elements as a validity
        check on the provided new_proof. We first check the 'proof' is a valid subtree of our tree.
        Then we collect the keys and their node types that are present in the proof.
        The main things we assert are:
        1. old_keys + added_keys - removed_keys = new_keys
        2. since we collect also node types for each key, we also assert that the old keys have
           retained their node type and additionally, compressed nodes retained their merkle root.

        An attacker could construct a treap that is valid, but isn't the same as a treap
        that is a result of inserting and removing these elements into 'proof'. But it seems
        impossible to trick us because the attacker can't turn a compressed node into regular node,
        nor can they drop nodes. This leaves them with only the ability to manipulate the nodes
        inside the space of correct proof. But there is only one valid treap inside this space
        so if the result is a valid treap, it has to be the correct one.
        """
        # we should have two sets with empty intersection
        assert isinstance(added, set) and isinstance(removed, set)
        assert added.intersection(removed) == set()

        # Verify the compressed tree is the same as the tree we have
        proof_root = proof.compute_merkle_root()
        if self.merkle_root != proof_root:
            raise ErrMerkleRootMismatch(
                f"Expected: {self.merkle_root}, got: {proof_root}"
            )

        # compute old keys and new keys and collect their node types and merkle roots. We must ensure the compressed
        # nodes didn't change their merkle root or the attacker could change their children.
        ext_old_keys = proof.collect_keys(extended=True)
        old_keys = set((key, _type) for key, _type, _ in ext_old_keys)
        old_C_keys = set((key, _type, merkle_root) for (key, _type, merkle_root) in ext_old_keys if _type == "C")
        old_N_keys = set((key, _type) for (key, _type, _) in ext_old_keys if _type == "N")

        ext_new_keys = new_proof.collect_keys(extended=True)
        new_keys = set((key, _type) for (key, _type, _) in ext_new_keys)
        new_C_keys = set((key, _type, merkle_root) for (key, _type, merkle_root) in ext_new_keys if _type == "C")
        new_N_keys = set((key, _type) for (key, _type, _) in ext_new_keys if _type == "N")

        # The added and removed keys must have type node type "N" meaning they're not a compressed node
        added_keys = set([(to_key(el), "N") for el in added])
        removed_keys = set([(to_key(el), "N") for el in removed])

        # Verify warp
        assert removed_keys.intersection(old_N_keys) == removed_keys  # removed keys exist in old_N_keys
        assert added_keys.intersection(old_keys) == set()             # added keys don't exist in old_keys
        assert new_N_keys - old_N_keys == added_keys                  # the only new N type keys are added ones
        assert (old_keys | added_keys) - removed_keys == new_keys     # check the keys are what we expect
        assert is_treap(new_proof)                                    # the new state must be a valid treap
        assert old_C_keys == new_C_keys                               # same compressed nodes including merkle roots

        # Verify merkle root of new_proof by recomputing everything.
        new_proof.compute_merkle_root()

        return Acc(new_proof), new_proof
