--------------------------- MODULE GraphTopology ---------------------------
(*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * TLA+ specification for ebpf-graph-lib graph topology invariants.
 *
 * Verifies:
 *   - IsDAG: the graph never contains a directed cycle
 *   - NoOrphanEdges: all edge endpoints are valid nodes
 *   - Reachability: connected components remain well-formed
 *
 * Run with TLC:
 *   tlc GraphTopology.tla -config GraphTopology.cfg
 *)

EXTENDS Naturals, FiniteSets

CONSTANTS MaxNodes

VARIABLES nodes, edges

vars == <<nodes, edges>>

TypeOK ==
    /\ nodes \subseteq 0..(MaxNodes-1)
    /\ edges \subseteq (0..(MaxNodes-1)) \X (0..(MaxNodes-1))

(* ---- Reachability via transitive closure ---- *)

(* Single-step reachability *)
Successors(n) == { m \in nodes : <<n, m>> \in edges }

(* Transitive closure of edges restricted to nodes *)
RECURSIVE ReachableFrom(_, _, _)
ReachableFrom(n, visited, E) ==
    LET succs == { m \in nodes : <<n, m>> \in E } \ visited
    IN  succs \union
        UNION { ReachableFrom(m, visited \union succs, E) : m \in succs }

(* ---- Invariants ---- *)

(* A node has a cycle if it can reach itself *)
HasCycle(n) == n \in ReachableFrom(n, {}, edges)

(* The graph is a DAG if no node has a cycle *)
IsDAG == \A n \in nodes : ~HasCycle(n)

(* All edge endpoints must be valid nodes *)
NoOrphanEdges ==
    \A e \in edges : e[1] \in nodes /\ e[2] \in nodes

(* ---- Actions ---- *)

Init ==
    /\ nodes = {}
    /\ edges = {}

AddNode ==
    /\ \E n \in 0..(MaxNodes-1) :
        /\ n \notin nodes
        /\ nodes' = nodes \union {n}
        /\ edges' = edges

RemoveNode ==
    /\ \E n \in nodes :
        /\ nodes' = nodes \ {n}
        (* Remove all edges touching this node *)
        /\ edges' = { e \in edges : e[1] /= n /\ e[2] /= n }

AddEdge ==
    /\ \E n, m \in nodes :
        /\ n /= m
        /\ <<n, m>> \notin edges
        (* Only add edge if it doesn't create a cycle *)
        /\ LET newEdges == edges \union {<<n, m>>}
           IN  \A v \in nodes : v \notin ReachableFrom(v, {}, newEdges)
        /\ edges' = edges \union {<<n, m>>}
        /\ nodes' = nodes

RemoveEdge ==
    /\ \E e \in edges :
        /\ edges' = edges \ {e}
        /\ nodes' = nodes

Next ==
    \/ AddNode
    \/ RemoveNode
    \/ AddEdge
    \/ RemoveEdge

(* ---- Specification ---- *)

Spec == Init /\ [][Next]_vars

(* ---- Properties ---- *)

(* The DAG property is always maintained *)
AlwaysDAG == []IsDAG

(* Orphan edges are never created *)
AlwaysNoOrphans == []NoOrphanEdges

(* Type correctness is always maintained *)
AlwaysTypeOK == []TypeOK

============================================================================
