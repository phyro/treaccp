from treaccp import build_treaccp, join_proofs, ErrInvalidProof

elements = set(range(1000))
treap = build_treaccp(elements)
acc = treap.to_acc()

# Prove insertion for an element in a treap and use the proof to insert into accumulator
new_element = 1234
new_treap, proof = treap.insert(new_element)
assert new_treap.merkle_root != treap.merkle_root

acc, _ = acc.insert(new_element, proof)
assert acc.merkle_root == new_treap.merkle_root
assert acc.merkle_root != treap.merkle_root

# Repeat the same for removal
newer_treap, proof = new_treap.remove(new_element)

new_acc, _ = acc.remove(new_element, proof)

# The accumulator is the same as the starting treap
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

# We can also "warp" to new state without separately inserting or removing elements
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
# we warp from state "joined_proof" to new state "newer_proof" without inserting or removing elements individually
acc2, _ = acc2.warp(
    joined_proof, set(insert_elements), set(remove_elements), newer_proof
)

assert acc2.merkle_root == acc1.merkle_root

print("Check readme for details.")
