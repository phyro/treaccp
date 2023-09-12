import random
import math
import time
import unittest

from treaccp.nodes import (
    H,
    to_key,
    join_proofs,
    find_path,
    is_treap,
    ErrKeyNotInTree,
    ErrKeyInTree,
    ErrInvalidProof,
    ErrMerkleRootMismatch,
)

from treaccp.tree import build_treaccp


# Deterministic random for reproducibility
seed_rng = str(random.random())
RNG_SEED = int(H("Blockchains synchronize global communication." + seed_rng), 16)
random.seed(RNG_SEED)
print(f"Seed: {RNG_SEED}\n")


class TestTreaccp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.treap_10k_els = set(random.sample(list(range(100000)), 10000))
        cls.treap_10k = build_treaccp(cls.treap_10k_els)
        cls.treap_10_not_in_set = range(5000000, 5010000)

    def setUp(self):
        # Each test should start with this seed. This avoid the problem of test reproducibility
        # depending on the order and execution of other tests.
        random.seed(RNG_SEED)

    def test_treap(self):
        els = range(100)
        # Build two trees, one as full tree and other as accumulator
        treap = build_treaccp(els)
        assert is_treap(treap.root)

        # Make it an invalid binary tree
        treap.root.left, treap.root.right = treap.root.right, treap.root.left
        try:
            assert is_treap(treap.root)
        except AssertionError as exc:
            assert exc.args[0] == "not a binary tree"
        treap.root.left, treap.root.right = (
            treap.root.right,
            treap.root.left,
        )  # switch back
        assert is_treap(treap.root)

        # Make it an invalid heap
        treap.root.prior, treap.root.right.prior = (
            treap.root.right.prior,
            treap.root.prior,
        )
        try:
            assert is_treap(treap.root)
        except AssertionError as exc:
            assert exc.args[0] == "not a heap"

    def test_irrelevant_order(self):
        els = list(range(1000))

        # Build two trees in a different order
        treap_A = build_treaccp(els)
        random.shuffle(els)
        treap_B = build_treaccp(els)

        # Assert that the merkle roots, including computed ones are equal
        self.assertEqual(treap_A.merkle_root, treap_B.merkle_root)
        computed_A = treap_A.root.compute_merkle_root()
        computed_B = treap_B.root.compute_merkle_root()
        self.assertEqual(computed_A, computed_B)
        self.assertEqual(computed_A, treap_A.merkle_root)

    def test_inclusion_proof(self):
        treap = self.treap_10k
        el_in_set = next(iter(self.treap_10k_els))  # takes one element from the set
        els_not_in_set = self.treap_10_not_in_set

        # Prove and verify inclusion
        inc_proof = treap.prove_inclusion(el_in_set)
        self.assertTrue(treap.verify_inclusion(el_in_set, inc_proof))

        # Fail verifying inclusion for an element not in the tree
        with self.assertRaises(ErrInvalidProof):
            treap.verify_inclusion(els_not_in_set[0], inc_proof)

        # Fail proving inclusion for an element not in the tree
        with self.assertRaises(ErrKeyNotInTree):
            treap.prove_inclusion(els_not_in_set[0])

        # Remove the key from the tree (changes merkle_root)
        removed_treap, _ = treap.remove(el_in_set, prove=False)

        # The inclusion proof from before no longer works
        with self.assertRaises(ErrMerkleRootMismatch):
            removed_treap.verify_inclusion(el_in_set, inc_proof)

        # Fail proving inclusion for the removed element
        with self.assertRaises(ErrKeyNotInTree):
            removed_treap.prove_inclusion(el_in_set)

    def test_exclusion_proof(self):
        treap = self.treap_10k
        el_in_set = next(iter(self.treap_10k_els))  # takes one element from the set
        els_not_in_set = self.treap_10_not_in_set

        # Prove and verify exclusion
        exc_proof = treap.prove_exclusion(els_not_in_set[0])
        self.assertTrue(treap.verify_exclusion(els_not_in_set[0], exc_proof))

        # Fail proving exclusion for an element in the tree
        with self.assertRaises(ErrKeyInTree):
            treap.prove_exclusion(el_in_set)

        # Fail verifying exclusion for an element that wasn't proven
        with self.assertRaises(ErrInvalidProof):
            treap.verify_exclusion(-1, exc_proof)

        # Insert the key in the tree (changes merkle_root) and test merkle_root error
        inserted_treap, _ = treap.insert(els_not_in_set[0], prove=False)
        with self.assertRaises(ErrMerkleRootMismatch):
            inserted_treap.verify_exclusion(els_not_in_set[0], exc_proof)

        # Fail proving exclusion, the key is now in the tree
        with self.assertRaises(ErrKeyInTree):
            inserted_treap.prove_exclusion(els_not_in_set[0])

    def test_join_proofs(self):
        els = [5, 10, 2, 7, 12, 4, 8, 9]
        treap = build_treaccp(els)

        proof_a = treap.prove_inclusion(12)

        with self.assertRaises(ErrInvalidProof):
            treap.verify_inclusion(2, proof_a)

        proof_b = treap.prove_inclusion(2)
        proof_c = treap.prove_exclusion(3)
        treap.verify_exclusion(3, proof_c)

        joined = join_proofs([proof_a, proof_b, proof_c])
        treap.verify_inclusion(12, joined)
        treap.verify_inclusion(4, joined)

    def test_inclusion_exclusion(self):
        els = list(range(10000))
        random.shuffle(els)

        start = time.time()
        treap = build_treaccp(els)
        end = time.time()
        print(f"build treap: {end - start}")

        for el in els[:1000]:
            inc_proof = treap.prove_inclusion(el)
            self.assertTrue(treap.verify_inclusion(el, inc_proof))
            self.assertTrue(treap.verify_inclusions([el], inc_proof))

            # Remove the element
            treap, _ = treap.remove(el, prove=False)
            # Assert that old proof is no longer valid (it's a different tree)
            with self.assertRaises(ErrMerkleRootMismatch):
                treap.verify_inclusion(el, inc_proof)
            with self.assertRaises(ErrMerkleRootMismatch):
                treap.verify_inclusions([el], inc_proof)

            # Assert you can't prove inclusion because the element is not in the tree
            with self.assertRaises(ErrKeyNotInTree):
                inc_proof = treap.prove_inclusion(el)

            # Assert you can prove exclusion of key
            exc_proof = treap.prove_exclusion(el)
            self.assertTrue(treap.verify_exclusion(el, exc_proof))

            # Make the tree the same
            treap, _ = treap.insert(el, prove=False)

            # Assert that old proof is no longer valid (it's a different tree)
            with self.assertRaises(ErrMerkleRootMismatch):
                treap.verify_exclusion(el, exc_proof)

            # Assert you can't prove exclusion because the element is in the tree
            with self.assertRaises(ErrKeyInTree):
                inc_proof = treap.prove_exclusion(el)

    def test_acc_insert(self):
        els = [5, 10, 2, 7, 12]
        # Build two trees, one as full tree and other as accumulator
        treap = build_treaccp(els)
        acc = treap.to_acc()
        assert treap.merkle_root == acc.merkle_root

        el = 8
        treap, proof = treap.insert(el)
        acc, _ = acc.insert(el, proof)
        assert treap.merkle_root == acc.merkle_root

    def test_acc_insert_large(self):
        size = 1000
        els = list(range(size))
        random.shuffle(els)
        # Build two trees, one as full tree and other as accumulator
        treap = build_treaccp(els)
        acc = treap.to_acc()
        assert treap.merkle_root == acc.merkle_root

        insert_els = list(range(size + 1, size + (int(size / 2))))
        random.shuffle(insert_els)
        for el in insert_els:
            treap, proof = treap.insert(el)
            acc, _ = acc.insert(el, proof)
            assert treap.merkle_root == acc.merkle_root

    def test_acc_insert_batch(self):
        size = 1000
        els = list(range(size))
        random.shuffle(els)
        # Build two trees, one as full tree and other as accumulator
        treap = build_treaccp(els)
        acc = treap.to_acc()
        assert treap.merkle_root == acc.merkle_root

        insert_els = list(range(size + 1, size + (int(size / 10))))
        random.shuffle(insert_els)

        start = time.time()
        new_treap, proof = treap.insert_many(insert_els)
        new_acc, compressed_tree = acc.insert_many(insert_els, proof)
        assert (
            new_treap.merkle_root != treap.merkle_root
        )  # sanity check: we changed the tree
        assert new_treap.merkle_root == new_acc.merkle_root
        print(f"c3 time: {time.time() - start}")

    def test_acc_remove(self):
        els = [5, 10, 2, 7, 12]
        # Build two trees, one as full tree and other as accumulator
        treap = build_treaccp(els)
        acc = treap.to_acc()
        assert treap.merkle_root == acc.merkle_root

        el = 7
        treap, proof = treap.remove(el)
        acc, _ = acc.remove(el, proof)
        assert treap.merkle_root == acc.merkle_root

    def test_acc_remove_large(self):
        size = 1000
        els = list(range(size))
        random.shuffle(els)
        # Build two trees, one as full tree and other as accumulator
        treap = build_treaccp(els)
        acc = treap.to_acc()
        assert treap.merkle_root == acc.merkle_root

        random.shuffle(els)
        for el in els[: int(size / 10)]:
            treap, proof = treap.remove(el)
            acc, _ = acc.remove(el, proof)
            assert treap.merkle_root == acc.merkle_root

    def test_batch_insertions_deletions(self):
        size = 1000
        els = list(range(size))
        random.shuffle(els)
        # Build two trees, one as full tree and other as accumulator
        start = time.time()
        treap = build_treaccp(els)
        acc = treap.to_acc()
        print(f"build treap time: {time.time() - start}")
        assert treap.merkle_root == acc.merkle_root

        insert_els = list(range(size + 1, size + (int(size / 10))))
        random.shuffle(insert_els)
        remove_els = random.sample(els, int(size / 10))

        # We prepare insert and remove proofs separately to measure time
        start = time.time()
        proofs = []
        for el in insert_els:
            proof = treap.insert_proof(el)
            assert treap.merkle_root == proof.merkle_root  # sanity check
            proofs.append(proof)
        for el in remove_els:
            proof = treap.remove_proof(el)
            assert treap.merkle_root == proof.merkle_root  # sanity check
            proofs.append(proof)
        print(f"proof calculation time: {time.time() - start}")

        # Join all the insert proofs into one
        start = time.time()
        joined_proof = join_proofs(proofs)
        # Use the joint proof as a compressed tree that gets updated
        compressed_tree = joined_proof
        print(f"proof join time: {time.time() - start}")

        # Insert and remove regular tree
        start = time.time()
        assert is_treap(treap.root)
        treap, _ = treap.insert_many(insert_els, prove=False)
        assert is_treap(treap.root)
        treap, _ = treap.remove_many(remove_els, prove=False)
        assert is_treap(treap.root)
        print(f"insert/remove regular time: {time.time() - start}")

        # insert and remove into accumulator
        start = time.time()
        acc, compressed_tree = acc.insert_many(insert_els, compressed_tree)
        acc, compressed_tree = acc.remove_many(remove_els, compressed_tree)
        print(f"insert/remove acc time: {time.time() - start}")
        assert treap.merkle_root == acc.merkle_root

    def test_treap_actions(self):
        els = [5, 10, 2, 7, 12]
        treap = build_treaccp(els)

        assert treap.find(7).key == to_key(7)
        assert treap.find(15) is None

        treap, _ = treap.remove(10, prove=False)
        treap, _ = treap.remove(5, prove=False)

        assert treap.find(5) is None
        assert treap.find(7).key == to_key(7)
        m1 = treap.merkle_root

        # Shuffling the keys should produce the exact same tree
        els2 = random.sample(els, len(els))
        treap = build_treaccp(els2)

        assert treap.find(7).key == to_key(7)
        assert treap.find(15) is None

        treap, _ = treap.remove(10, prove=False)
        treap, _ = treap.remove(5, prove=False)

        assert treap.find(5) is None
        assert treap.find(7).key == to_key(7)
        m2 = treap.merkle_root
        assert m1 == m2

    def test_persistent(self):
        els = [5, 10, 2, 7, 12]
        treap = build_treaccp(els)

        new_treap, _ = treap.remove(5)
        assert treap.find(5) is not None
        assert new_treap.find(5) is None

    def test_insert_duplicate(self):
        els = [5, 10, 2, 7, 12]
        treap = build_treaccp(els)

        with self.assertRaises(ErrKeyInTree):
            treap.insert(5)

    def test_remove_not_in_set(self):
        els = [5, 10, 2, 7, 12]
        treap = build_treaccp(els)

        with self.assertRaises(ErrKeyNotInTree):
            treap.remove(8)

    @unittest.skip("this one is just for testing max depth and average depth")
    def test_depth(self):
        for i in range(1, 30):
            size = 50000 * i
            print("size:", size)
            optimal_depth = math.ceil(math.log(size, 2))
            els = list(range(size))
            start = time.time()
            treap = build_treaccp(els)
            print(f"build treap time: {time.time() - start}")

            def depth(t):
                if t is None:
                    return 0
                return 1 + max(
                    depth(t.left) if t.left else 0, depth(t.right) if t.right else 0
                )

            def subsample_avg_med(t, subsample):
                """Returns average and median depth of the subsample."""
                depths = []
                for el in subsample:
                    path = find_path(t, to_key(el))
                    assert (
                        path[-1] is not None
                    )  # sanity check: the element is in the tree
                    depths.append(len(path))
                return sum(depths) / float(len(depths)), depths[int(len(depths) / 2)]

            result = depth(treap.root)
            avg_depth, median = subsample_avg_med(treap.root, random.sample(els, 200))
            print(f"optimal depth: {optimal_depth}, max tree depth: {result}")
            print(f"avg depth: {avg_depth}, median: {median}")

    def test_rnd_scenarios(self):
        for cnt in range(11, 100):
            els = range(18000, 18000 + cnt)
            treap = build_treaccp(els)
            assert is_treap(treap.root)

            # remove and generate proof
            new_treap, _ = treap.remove_many(els[:10])
            assert new_treap.merkle_root != treap.merkle_root
            new_treap, _ = new_treap.insert_many(els[:10])
            assert new_treap.merkle_root == treap.merkle_root

            cnt += 1

    def test_warp_state(self):
        els = range(100)
        treap = build_treaccp(els)
        acc1 = treap.to_acc()
        acc2 = treap.to_acc()

        remove_els = [15, 8, 33, 88]
        insert_els = [104, 201]
        proofs = []
        for el in insert_els:
            proofs.append(treap.insert_proof(el))
        for el in remove_els:
            proofs.append(treap.remove_proof(el))
        joined_proof = join_proofs(proofs)
        treap, _ = treap.insert_many(insert_els, prove=False)
        treap, _ = treap.remove_many(remove_els, prove=False)

        acc1, t1 = acc1.insert_many(insert_els, joined_proof)
        acc1, t2 = acc1.remove_many(remove_els, t1)

        assert acc1.merkle_root == treap.merkle_root

        acc2, warp_tree = acc2.warp(joined_proof, set(insert_els), set(remove_els), t2)
        assert acc2.merkle_root == treap.merkle_root
        assert acc2.merkle_root == acc1.merkle_root

    def test_warp_state_large(self):
        treap = self.treap_10k
        acc1 = self.treap_10k.to_acc()
        acc2 = self.treap_10k.to_acc()

        remove_els = list(self.treap_10k_els)[:2000]
        insert_els = self.treap_10_not_in_set[:2000]
        proofs = []
        for el in insert_els:
            proofs.append(treap.insert_proof(el))
        for el in remove_els:
            proofs.append(treap.remove_proof(el))
        joined_proof = join_proofs(proofs)

        start = time.time()
        treap, _ = treap.insert_many(insert_els, prove=False)
        treap, _ = treap.remove_many(remove_els, prove=False)
        print(f"regular insert/remove time: {time.time() - start}")

        start = time.time()
        acc1, t1 = acc1.insert_many(insert_els, joined_proof)
        acc1, t2 = acc1.remove_many(remove_els, t1)
        print(f"acc insert/remove time: {time.time() - start}")

        assert acc1.merkle_root == treap.merkle_root

        start = time.time()
        acc2, warp_tree = acc2.warp(joined_proof, set(insert_els), set(remove_els), t2)
        assert acc2.merkle_root == treap.merkle_root
        assert acc2.merkle_root == acc1.merkle_root
        print(f"acc warp insert/remove time: {time.time() - start}")


if __name__ == "__main__":
    unittest.main()
