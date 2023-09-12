"""Implementation of merkle treap nodes whose keys and priorities are pseudorandom 32 byte integers.
Treap is able to prove inclusion of a key by showing a proof that takes a form of a compressed subtree
which allows us to perform an action like 'find' to prove a key is or isn't in the tree. One way to
visualize the tree is to think of each node as a random (2^256, 2^256) point in a 2D space and we can
prove a point is or isn't in our space. Because all the data a node holds is pseudorandom, it doesn't
really hold information about the elements themselves, just a hash commitment to them.
"""

import hashlib


def H(_input):
    """Hash function used to generate pseudorandom data."""
    _input = str(_input)
    return hashlib.sha256(_input.encode("utf-8")).hexdigest()


# We treat empty leaves as a hash to avoid any possible tampering
HASH_NONE = H("None")


def to_key(el):
    return int(H(el), 16)


def to_priority(key):
    return int(H(str(key)), 16)


class ErrKeyNotInTree(Exception):
    pass


class ErrKeyInTree(Exception):
    pass


class ErrMerkleRootMismatch(Exception):
    pass

class ErrInvalidProof(Exception):
    pass


class ErrTouchedCompressedNode(Exception):
    """An error when we have reached a compressed node when we shouldn't have.
    An example is an exclusion proof which is a failed search on a compressed tree without touching compressed parts."""

    pass


class CompressedNode:
    """A compressed node is a node that holds only merkle roots of its children."""

    def __init__(self, key, left_hash, right_hash):
        self.key = key
        self.prior = to_priority(self.key)
        self.left_hash = left_hash
        self.right_hash = right_hash
        self.merkle_root = self.compute_merkle_root()

    def compute_merkle_root(self):
        node_hash = str(self.key) + str(self.prior)
        hash_input = [node_hash, self.left_hash, self.right_hash]
        merkle_root = H("".join(hash_input))

        return merkle_root

    def collect_keys(self, extended=False):
        """Compressed treap only knows about its own key."""
        if extended:
            return set([(self.key, "C", self.merkle_root)])

        return set([self.key])


class Node:
    """A treap where keys and priorities are expected to be pseudorandom."""

    def __init__(
        self,
        key,
        prior=None,  # even though it's deterministically derived, it can be passed as an optimization
        left=None,
        right=None,
        recursive_merkle=True,
    ):
        self.key = key
        self.prior = to_priority(self.key) if prior is None else prior
        self.left = left
        self.right = right
        self.merkle_root = self.compute_merkle_root(
            recurse=recursive_merkle, verify=False
        )

    def compress(self):
        """Returns the compressed representation of the node."""
        left_hash = self.left.merkle_root if self.left else HASH_NONE
        right_hash = self.right.merkle_root if self.right else HASH_NONE
        return CompressedNode(self.key, left_hash, right_hash)

    def compute_merkle_root(self, recurse=True, verify=True):
        """
        Given a tree

              N1
            /    \
           N2    N3

        computes the merkle root of N1 as H(N1.key || N1.priority || N2.merkle_root || N3.merkle_root).
        The merkle root is thus the hash of the subtree merkle roots and the node content.

        Note that by default this traverses the whole tree and computes merkle root for every node.
        We recompute the whole tree merkle roots for proofs we are given to ensure they're correct.
        """

        def _tree_hash(t, recurse):
            if t is None:
                return HASH_NONE
            if recurse:
                # we don't need to pass recurse because it's True by default
                return t.compute_merkle_root()
            return t.merkle_root

        # We commit to priorities even though they're derived from keys. This way, if we verify the merkle root
        # for a proof is correct, we know the data in the proof (keys, priorities) could not have been tampered.
        node_hash = str(self.key) + str(self.prior)
        hash_input = [
            node_hash,
            _tree_hash(self.left, recurse),
            _tree_hash(self.right, recurse),
        ]
        merkle_root = H("".join(hash_input))

        # We also verify the merkle_root is correct. The only case where this wouldn't be true is if an attacker
        # set the merkle_root to a wrong value in an attempt to fool us.
        if verify:
            assert self.merkle_root == merkle_root

        return merkle_root

    def _compress_tree_for(self, key):
        """Construct a compressed tree from root to given key.

        Given a tree
                                    _compress_tree_for(86.key)
                  35                         N
                /    \                      / \
              12     80         =>         C   N
              /     /  \                      /  \
             5     42   86                   C    N
            / \        /  \                      / \
        None  None  None  None                None  None

        Since nodes don't contain elements, a subtree can't leak any element. Nodes labeled N are regular nodes.
        Nodes labeled C are compressed nodes meaning they only hold merkle roots of their children.
        """
        if self is None:
            raise ErrKeyNotInTree(f"{key}")
        if self.key == key:
            return Node(
                key=self.key,
                prior=self.prior,
                left=self.left.compress() if self.left else None,
                right=self.right.compress() if self.right else None,
            )

        if key > self.key:
            if not self.right:
                raise ErrKeyNotInTree(f"{key}")
            right = self.right._compress_tree_for(key)
            return Node(
                key=self.key,
                prior=self.prior,
                left=self.left.compress() if self.left else None,
                right=right,
                recursive_merkle=False,  # to avoid expensive recomputation
            )
        else:
            if not self.left:
                raise ErrKeyNotInTree(f"{key}")
            left = self.left._compress_tree_for(key)
            return Node(
                key=self.key,
                prior=self.prior,
                left=left,
                right=self.right.compress() if self.right else None,
                recursive_merkle=False,  # to avoid expensive recomputation
            )

    def prove_inclusion(self, key):
        """An inclusion proof is a compressed version of the tree that keeps nodes in the search path intact,
        but compresses all other nodes.

        Given a tree
                                    Proof for 86          Proof for 80          Proof for 5
                  35                    N                    N                      N
                /    \                 / \                  / \                    / \
              12     80        =>     C   N          =>    C   N         =>       N   C
              /     /  \                 / \                  / \                / \
             5     42   86              C   N                C   C              N  None
            / \        /  \                / \                                 / \
        None  None  None  None          None  None                          None  None

        Where N is a regular Node that holds key, priority and its children, C is a compressed node
        holding only merkle roots of its children and None is when a node has no child.

        To prove 5, we simply construct a compressed version of a tree that has enough information to "find" the
        the key 5 **without touching a compressed node** during search.
        """
        proof = self._compress_tree_for(key)
        assert self.merkle_root == proof.compute_merkle_root()  # sanity check

        return proof

    def verify_inclusion(self, key, proof):
        """Verifies a key is included in the set."""
        return self.verify_inclusions([key], proof)

    def collect_keys(self, extended=False):
        """Returns a set of keys in the tree, optionally with the node type that holds the key."""
        cur = None
        if extended:
            cur = set([(self.key, "N", self.merkle_root)])
        else:
            cur = set([self.key])

        # We collect the keys recursively. Compressed nodes return only their key.
        left_keys = set()
        if self.left:
            left_keys = self.left.collect_keys(extended=extended)
        right_keys = set()
        if self.right:
            right_keys = self.right.collect_keys(extended=extended)

        return left_keys | cur | right_keys

    def verify_inclusions(self, keys, proof):
        """Verifies that multiple keys are included in the set."""
        # Verify the compressed tree is the same as the tree we have
        proof_root = proof.compute_merkle_root()
        if self.merkle_root != proof_root:
            raise ErrMerkleRootMismatch(
                f"Expected: {self.merkle_root}, got: {proof_root}"
            )

        # Collect the keys and compare
        observed_keys = proof.collect_keys()
        for key in keys:
            if key not in observed_keys:
                raise ErrInvalidProof(f"{key}")

        return True

    def prove_exclusion(self, key):
        """We prove exclusion by showing an inclusion proof for a position at which the key should be, but is None.

        Given a tree

                    35
                  /    \
                 12    80
                /     /  \
               5     42   86
              / \
           None None

        If we want to prove 50 is not in the tree, we have to prove that finding the key 50 would return a None.
        The proof is thus an inclusion proof (compressed tree) for 42 which includes both of its None children:

              N
             / \
            C   N
               / \
              N   C
             / \
          None  None

        We prove exclusion by verifying the merkle root of the compressed tree and proving that a search on this
        compressed tree doesn't touch compressed 'C' nodes and arrives at None.
        """
        path = find_path(self, key)
        if path[-1] is not None:
            raise ErrKeyInTree(f"{key}")

        last_touched_key = path[-2].key
        proof = self.prove_inclusion(last_touched_key)

        return proof

    def verify_exclusion(self, key, proof):
        """Verifies that a key is not in the set."""
        return self.verify_exclusions([key], proof)

    def verify_exclusions(self, keys, proof):
        """Verifies that keys are not in the set."""

        # Verify the compressed tree is the same as the tree we have
        proof_root = proof.compute_merkle_root()
        if self.merkle_root != proof_root:
            raise ErrMerkleRootMismatch(
                f"Expected: {self.merkle_root}, got: {proof_root}"
            )

        for key in keys:
            # We search the key in the compressed tree. Reaching a CompressedNode during search should never
            # happen because it's impossible to know if it splits further. We thus require the search to arrive
            # at None node without ever touching a compressed node.
            try:
                node = find(proof, key)
            except ErrTouchedCompressedNode:
                raise ErrInvalidProof
            if node is not None:
                raise ErrKeyInTree(f"{key}")

        return True

    def insert_proof(self, key):
        return insert_proof(self, key)

    def remove_proof(self, key):
        return remove_proof(self, key)

    def find(self, key):
        return find(self, key)

    def insert(self, key, prove=True):
        return self.insert_many([key], prove=prove)

    def insert_many(self, keys, prove=True):
        proof = None
        if prove:
            proofs = []
            for key in keys:
                proofs.append(insert_proof(self, key))
            proof = join_proofs(proofs)

        res = self
        for key in keys:
            res = insert(res, key)
        return res, proof

    def remove(self, key, prove=True):
        return self.remove_many([key], prove=prove)

    def remove_many(self, keys, prove=True):
        proof = None
        if prove:
            proofs = []
            for key in keys:
                proofs.append(remove_proof(self, key))
            proof = join_proofs(proofs)

        res = self
        for key in keys:
            res = remove(res, key)
        return res, proof


def split(t, key, equal_on_the_left=False):
    if isinstance(t, CompressedNode):
        raise ErrTouchedCompressedNode("split")
    if not t:
        return None, None

    if t.key < key or (equal_on_the_left and t.key == key):
        L, R = split(t.right, key, equal_on_the_left)
        new_t = Node(
            key=t.key,  # we set key and prior because element could be None when inserting via proof
            prior=t.prior,
            left=t.left,
            right=L,
            recursive_merkle=False,
        )
        return new_t, R
    else:
        L, R = split(t.left, key, equal_on_the_left)
        new_t = Node(
            key=t.key,  # we set key and prior because element could be None when inserting via proof
            prior=t.prior,
            left=R,
            right=t.right,
            recursive_merkle=False,
        )
        return L, new_t


def merge(t1, t2):
    if isinstance(t1, CompressedNode) or isinstance(t2, CompressedNode):
        raise ErrTouchedCompressedNode("merge")
    if not t1:
        return t2
    if not t2:
        return t1

    if t1.prior > t2.prior:
        return Node(
            key=t1.key,
            prior=t1.prior,  # we set prior for optimization
            left=t1.left,
            right=merge(t1.right, t2),
            recursive_merkle=False,
        )
    else:
        return Node(
            key=t2.key,
            prior=t2.prior,  # we set prior for optimization
            left=merge(t1, t2.left),
            right=t2.right,
            recursive_merkle=False,
        )


def find(t, key):
    if isinstance(t, CompressedNode):
        raise ErrTouchedCompressedNode("Searched through compressed nodes.")
    if t is None:
        return None
    if t.key == key:
        return t

    return find(t.right if key >= t.key else t.left, key)


def insert(t, key):
    L, R = split(t, key)
    # Check if the key already exists
    if find(R, key) is not None:
        raise ErrKeyInTree(f"key {key} is already in the tree")
        # Alternatively we could just merge L and R back
        # return merge(L, R)

    new_node = Node(key)
    return merge(L, merge(new_node, R))


def insert_proof(t, key):
    tree_path = find_path(t, key)
    if tree_path[-1] is not None:
        raise ErrKeyInTree(f"key {key} in the tree")

    # proofs = [
    #     t._compress_tree_for(tree_path[-2].key),
    #     t.prove_exclusion(tree_path[-2].key + 1),
    #     t.prove_exclusion(tree_path[-2].key - 1),
    # ]
    # proof = join_proofs(proofs)
    proof = t.prove_exclusion(tree_path[-2].key + 1)
    assert t.merkle_root == proof.merkle_root  # sanity check

    return proof


def remove(t, key):
    L, R = split(t, key)
    if R:
        L2, R2 = split(R, key, equal_on_the_left=True)
        if L2 is None:
            raise ErrKeyNotInTree(f"key {key} not in tree")
        # Note: If L2 is None, it means the element we're removing is not in the tree. We merge L and R2 even
        # when we have nothing to remove.
        return merge(L, R2)

    return merge(L, R)


def remove_proof(t, key):
    tree_path = find_path(t, key)
    if tree_path[-1] is None:
        raise ErrKeyNotInTree(f"key {key} not in tree")

    proofs = [
        # t._compress_tree_for(tree_path[-1].key),
        t.prove_exclusion(tree_path[-1].key + 1),
        t.prove_exclusion(tree_path[-1].key - 1),
    ]
    proof = join_proofs(proofs)
    assert t.merkle_root == proof.merkle_root  # sanity check

    return proof


def find_path(t, key):
    """Returns the path to the given key."""
    if t is None:
        return [None]
    if t.key == key:
        return [t]

    path = find_path(t.right if key >= t.key else t.left, key)
    return [t] + path


def print_treap(root, indent=""):
    def _short(a):
        return str(a)[:7]
    if root is not None:
        if not isinstance(root, CompressedNode):
            print_treap(root.right, indent + "    │")

        print(indent + "── " + f"Key: {_short(root.key)}, Prior: {_short(root.prior)}, merkle_root: {_short(root.merkle_root)}")

        if not isinstance(root, CompressedNode):
            print_treap(root.left, indent + "    │")


def join_proofs(proofs):
    # assert they all have the same merkle root
    merkle_roots = set([proof.compute_merkle_root() for proof in proofs])
    assert len(merkle_roots) == 1

    joined = proofs[0]
    for proof in proofs[1:]:
        joined = join_two_proofs(joined, proof)

    assert merkle_roots.pop() == joined.merkle_root  # sanity check
    return joined


def join_two_proofs(a, b):
    """Joins proofs A and B by creating a relaxed version of both trees."""

    def most_relaxed(a, b):
        """Returns the most relaxed node type."""
        # The order in which we prefer nodes because they reveal more data
        relax_order = {Node: 1, CompressedNode: 2, type(None): 3}
        order_a = relax_order[type(a)]
        order_b = relax_order[type(b)]
        if order_a < order_b:
            return a
        return b

    # We only continue recursively if both are Node types
    if not isinstance(a, Node) and not isinstance(b, Node):
        # If neither are nodes which continue, return the relaxed one
        return most_relaxed(a, b)
    if isinstance(a, Node) and not isinstance(b, Node):
        return a
    if isinstance(b, Node) and not isinstance(a, Node):
        return b
    if isinstance(a, Node) and isinstance(b, Node):
        # Note: we don't need to recurse for merkle trees because the recursive calls to join_two_proofs will
        # already correctly compute the merkle roots of the children correctly
        return Node(
            key=a.key,
            prior=a.prior,  # we set prior for optimization
            left=join_two_proofs(a.left, b.left),
            right=join_two_proofs(a.right, b.right),
            recursive_merkle=False,
        )

    raise ValueError("Shouldn't reach this")


def is_treap(root):
    def verify_heap(t):
        if isinstance(t, CompressedNode):
            return t.prior

        max_left = verify_heap(t.left) if t.left else -1
        max_right = verify_heap(t.right) if t.right else -1

        assert t.prior > max_left and t.prior > max_right, "not a heap"

        return t.prior

    def verify_binary_tree(t):
        if isinstance(t, CompressedNode):
            return
        if t.left:
            assert t.key > t.left.key, "not a binary tree"
            verify_binary_tree(t.left)
        if t.right:
            assert t.key < t.right.key, "not a binary tree"
            verify_binary_tree(t.right)

    verify_heap(root)
    verify_binary_tree(root)

    return True


def build_treap(elements):
    root = None
    for el in elements:
        key = to_key(el)
        root = insert(root, key)
    return root
