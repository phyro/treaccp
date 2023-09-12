# Treaccp

**This work has not been reviewed in any way. DO NOT USE IN PRODUCTION!**

Minimal implementation of a [treap](https://en.wikipedia.org/wiki/Treap) based persistent universal accumulator. Maybe.

Example usage:

```python
from treaccp import build_treaccp, join_proofs

elements = set(range(1000))
treap = build_treaccp(elements)
acc = treap.to_acc()

# Prove insertion for an element in a treap and use the proof to insert into accumulator
new_element = 1234
# NOTE: We could insert the element without building the insertion proof by passing `prove=False`
new_treap, proof = treap.insert(new_element)
assert new_treap.merkle_root != treap.merkle_root

acc, _ = acc.insert(new_element, proof)
assert acc.merkle_root != treap.merkle_root
assert acc.merkle_root == new_treap.merkle_root

# Prove removal for an element
new_treap, proof = new_treap.remove(new_element)
new_acc, _ = acc.remove(new_element, proof)
assert new_treap.merkle_root == new_acc.merkle_root

# Additionally, because treaps are deterministic, the resulting treap has the same merkle root as
# the treap we started with because we added the element and removed it.
assert new_acc.merkle_root == treap.merkle_root

# We can also prove set membership and non-membership
inclusion_proof = treap.prove_inclusion(103)
exclusion_proof = treap.prove_exclusion(1003)
assert new_acc.verify_inclusion(103, inclusion_proof)
assert new_acc.verify_exclusion(1003, exclusion_proof)
try:
    new_acc.verify_exclusion(103, exclusion_proof)
except ErrInvalidProof:
    print("Caught an invalid exclusion proof.")
```


### Properties

We build a Treap with both the keys and priorities being random, but deterministic. A key is a hash of the element and priority is a hash of the key. Since there's a single valid treap for a set of pairs (key, priority), this means that no matter in which order we add elements in the tree, if the set of elements is the same, we will get the same tree. Our treap is also a merkle tree so not only will we get the same tree, we'll also get the exact same merkle root regardless of the order in which the elements were added. Having both key and priority pseudorandom makes them uniformly distributed and should thus make for a well balanced tree. Moreover, since the key is a hash, it can be made hard to degenerate the tree because the attacker would need to do hashcash PoW to manipulate key or priority values.

The size of the accumulator is 32 bytes.

Operations:
1. Prove element `inclusion` and `exclusion` with tree inclusion proofs in Log(n) time and space.
2. We can `insert` and `delete` elements to/from the acumulator in Log(n) time and space.
3. We can also speed up things when inserting and removing many elements by "warping" from current accumulator state to a new state without adding and removing elements, but by only verifying that the new accumulator state is correct. This operation takes N*Log(N) time and space, but is faster than inserting and removing elements individually.

_NOTE: Operations are experimental, warp even more so and could be fundamentally flawed._

#### Time complexity


| Treap Operations       | Average time complexity |
| --------------- | ------------- |
| Insert          |  O(Log(N))  |
| Remove          |  O(Log(N))  |
| Prove insertion |  O(Log(N))  |
| Prove removal   |  O(Log(N))  |
| Prove inclusion |  O(Log(N))  |
| Prove exclusion |  O(Log(N))  |

| Accumulator Operations       | Average Time complexity |
| --------------- | ------------- |
| Verify inclusion |  O(Log(N))  |
| Verify exclusion |  O(Log(N))  |
| AccInsert       |  O(Log(N))  |
| AccRemove       |  O(Log(N))  |

We can build a treap of size N by doing N inserts making the build time complexity N*Log(N).

Inclusion and exclusion proofs are a subtree which we can verify is indeed the subtree of our accumulator by computing the merkle root of the subtree.

##### Batching proofs

Since inclusion and exclusion proofs are a subtree, they can be aggregated by making a union of the proofs which results in a larger subtree, but since there's going to be an overlap, the sum will be smaller than the two individual subtrees. We can use this aggregated proof to perform multiple insert/remove operations on the accumulator.

##### State Warp

_NOTE: As mentioned, the author could be incorrect about this as it was coded without a deep research._

If we're removing 5000 elements and adding 5000 elements, then we have 10000*Log(N) operations. There's another way to update the state by receiving the updated tree and verifying it rather than creating this tree by performing these operations.

Along with `proof` which is a subtree of our current state, we can also receive the updated subtree `new_proof`. To verify the new proof (or new state) is correct, we mostly have to check that we removed and added the correct elements and that the result is a valid treap. All the other elements in the tree must stay the same and we can verify this by checking their merkle proofs. With a single pass on the `new_proof` subtree, we can verify the given state update is correct without individual insertions and deletions.


Example usage:
```python
# Rather than inserting and removing elements individually, we can warp to a new state
elements = set(range(1000))
treap = build_treaccp(elements)
acc1 = treap.to_acc()
acc2 = treap.to_acc()

insert_elements = range(1001, 1100)
remove_elements = range(200, 300)

# Build a proof for insertions and deletions
proofs = []
for el in insert_elements:
    proofs.append(treap.insert_proof(el))
for el in remove_elements:
    proofs.append(treap.remove_proof(el))
joined_proof = join_proofs(proofs)

# We only insert elements, we've already proven them
acc1, new_proof = acc1.insert_many(insert_elements, joined_proof)
acc1, newer_proof = acc1.remove_many(remove_elements, new_proof)

# joined_proof - a proof for inserting and deleting elements
# newer_proof - state after insertion and deletions into joined_proof
# warp from state joined_proof to new state newer_proof without inserting or removing elements
acc2, _ = acc2.warp(joined_proof, set(insert_elements), set(remove_elements), newer_proof)

assert acc2.merkle_root == acc1.merkle_root
```


### Open questions

**How can we make it more resilient to degenerate attacks?**

There's probably quite a few ways. One way would be to require PoW on `key` hash. Another would be to start with a balanced treap with 2^32 points which are artificially created meaning that we don't know the elements that map to these keys. We can simply pick keys key as `x` coordinate in certain intervals that divide the space well and compute the merkle root of that tree. This however requires more storage.

**Treaps are good with sets, can we do more set operations?**

We probably could if we had keys that weren't pseudorandom. One thing that it would enable is doing range queries on elements.
