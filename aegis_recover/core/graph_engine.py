import math
import re
from typing import List, Dict, Set, Tuple
from collections import defaultdict
from .types import RecoveredFragment, RelationshipEdge, FileCategory

class FragmentGraphEngine:
    """Builds intelligent relationship graphs connecting disparate unallocated fragments."""

    def build_relationship_graph(
        self,
        fragments: List[RecoveredFragment],
        sector_gap_tolerance: int = 16
    ) -> List[RelationshipEdge]:
        """
        Analyzes pairs of recovered fragments and discovers structural,
        entity-based, and semantic relationships.
        """
        edges: List[RelationshipEdge] = []
        n = len(fragments)
        if n < 2:
            return edges

        # 1. Entity Index: map (entity_type, entity_val) -> list of fragment_ids
        entity_map = defaultdict(list)
        for frag in fragments:
            for entity in frag.entities:
                key = (entity.entity_type, entity.value.lower())
                entity_map[key].append(frag.fragment_id)
                # Also index domain names from emails
                if entity.entity_type == "email" and "@" in entity.value:
                    domain = entity.value.split("@")[1].lower()
                    entity_map[("domain", domain)].append(frag.fragment_id)

        # Connect fragments that share significant entities
        seen_pairs: Set[Tuple[str, str, str]] = set()
        for (etype, evalue), frag_ids in entity_map.items():
            unique_frags = list(dict.fromkeys(frag_ids))
            if 1 < len(unique_frags) <= 12:
                for i in range(len(unique_frags)):
                    for j in range(i + 1, len(unique_frags)):
                        pair = tuple(sorted([unique_frags[i], unique_frags[j]]))
                        pair_key = (pair[0], pair[1], "SHARED_ENTITY")
                        if pair_key not in seen_pairs:
                            seen_pairs.add(pair_key)
                            edges.append(RelationshipEdge(
                                source_id=pair[0],
                                target_id=pair[1],
                                relationship_type="SHARED_ENTITY",
                                confidence=0.90 if etype != "domain" else 0.82,
                                explanation=f"Fragments correlate via shared {etype.replace('_', ' ').title()}: '{evalue}'"
                            ))

        # 2. Sector Adjacency & Code/Document Continuation
        sorted_frags = sorted(fragments, key=lambda f: f.start_sector)
        for i in range(len(sorted_frags) - 1):
            curr_f = sorted_frags[i]
            next_f = sorted_frags[i + 1]

            gap = next_f.start_sector - curr_f.end_sector
            if 0 <= gap <= sector_gap_tolerance:
                # Same category continuation (e.g. source code split across bad sectors)
                if curr_f.category == next_f.category and curr_f.category in [FileCategory.SOURCE_CODE, FileCategory.DOCUMENT, FileCategory.IMAGE, FileCategory.DATABASE]:
                    pair = tuple(sorted([curr_f.fragment_id, next_f.fragment_id]))
                    pair_key = (pair[0], pair[1], "CONTINUATION")
                    if pair_key not in seen_pairs:
                        seen_pairs.add(pair_key)
                        conf = max(0.65, 0.96 - (gap * 0.04))
                        edges.append(RelationshipEdge(
                            source_id=curr_f.fragment_id,
                            target_id=next_f.fragment_id,
                            relationship_type="CONTINUATION",
                            confidence=round(conf, 2),
                            explanation=f"Storage cluster continuation across sector {curr_f.end_sector} -> {next_f.start_sector} (gap: {gap} sectors) with consistent format {curr_f.detected_type}"
                        ))
                elif (curr_f.category == FileCategory.DATABASE and next_f.category in [FileCategory.DOCUMENT, FileCategory.STRUCTURED_DATA]):
                    pair = tuple(sorted([curr_f.fragment_id, next_f.fragment_id]))
                    pair_key = (pair[0], pair[1], "SCHEMA_DATA")
                    if pair_key not in seen_pairs:
                        seen_pairs.add(pair_key)
                        edges.append(RelationshipEdge(
                            source_id=curr_f.fragment_id,
                            target_id=next_f.fragment_id,
                            relationship_type="SCHEMA_DATA",
                            confidence=0.85,
                            explanation="Database B-tree table structures correlate with subsequent record data."
                        ))

        # Update each fragment's linked_fragment_ids list
        link_dict = defaultdict(set)
        for edge in edges:
            link_dict[edge.source_id].add(edge.target_id)
            link_dict[edge.target_id].add(edge.source_id)

        for frag in fragments:
            frag.linked_fragment_ids = list(link_dict[frag.fragment_id])

        return edges

    def find_clusters(self, fragments: List[RecoveredFragment], edges: List[RelationshipEdge]) -> List[List[str]]:
        """Groups fragments into coherent reconstructed clusters using Union-Find."""
        parent = {f.fragment_id: f.fragment_id for f in fragments}

        def find(x):
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]

        def union(x, y):
            rx, ry = find(x), find(y)
            if rx != ry:
                parent[rx] = ry

        for edge in edges:
            if edge.confidence >= 0.70:
                union(edge.source_id, edge.target_id)

        clusters = defaultdict(list)
        for f in fragments:
            clusters[find(f.fragment_id)].append(f.fragment_id)

        return [c for c in clusters.values() if len(c) > 1]
