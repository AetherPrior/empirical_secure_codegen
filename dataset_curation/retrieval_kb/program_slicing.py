"""
This module implements Program Slicing.
"""
from difflib import Differ, unified_diff
import numpy as np
import networkx as nx
from tree_sitter import Parser, Language, TreeCursor, Tree, Node
import tree_sitter_python as tspy
import tree_sitter_c as tsc
from typing import List, Optional, Union, Dict, Set
from functools import reduce


def build_control_flow_graph(tree: Tree):
    graph = nx.DiGraph()
    root_node = tree.root_node
    graph.add_node(root_node.id, ast_node = None, text = "Entry")
    exit_node = id("ExitNode")
    graph.add_node(exit_node, ast_node = None, text = "Exit")

    def traverse_build_cfg(node: Node, graph: nx.DiGraph, previous_statements: Union[Node, List[Node]]):
        if "statement" in node.type:
            # Add new node for every statement
            graph.add_node(node.id, ast_node = node, text = node.text.decode())
            if previous_statements is None:
                pass
            elif isinstance(previous_statements, list):
                for elem in previous_statements:
                    if elem:
                        graph.add_edge(elem.id, node.id, edge_type = "common")
            elif isinstance(previous_statements, Node):
                graph.add_edge(previous_statements.id, node.id, edge_type = "common")

            if node.type == "if_statement":
                if_exit_stat = []
                cond_node = node.child_by_field_name("condition")
                
                consequence_node = node.child_by_field_name("consequence")
                end_stat = traverse_build_cfg(consequence_node, graph, node)
                if isinstance(end_stat, list):
                    if_exit_stat.extend(end_stat)
                elif isinstance(end_stat, Node):
                    if_exit_stat.append(end_stat)
                alternative_node_list = node.children_by_field_name("alternative")
                if alternative_node_list:
                    for alter_node in alternative_node_list:
                        graph.add_node(alter_node.id, ast_node = alter_node, text = alter_node.text.decode())
                        graph.add_edge(node.id, alter_node.id)
                        end_stat = traverse_build_cfg(alter_node, graph, alter_node)
                        if isinstance(end_stat, list):
                            if_exit_stat.extend(end_stat)
                        elif isinstance(end_stat, Node):
                            if_exit_stat.append(end_stat)
                else:
                    if_exit_stat.append(node)
                previous_statements = if_exit_stat
            elif node.type in ["while_statement", "for_statement"]:
                body_node = node.child_by_field_name("body")
                previous_statements = traverse_build_cfg(body_node, graph, node)
                if isinstance(previous_statements, list):
                    for elem in previous_statements:
                        if elem:
                            graph.add_edge(elem.id, node.id, edge_type = "common")
                elif isinstance(previous_statements, Node):
                    # print(type(previous_statements))
                    graph.add_edge(previous_statements.id, node.id, edge_type = "common")
                previous_statements = node
            elif node.type == "return_statement":
                # graph.add_node(node.id, ast_node = node, text = node.text.decode())
                graph.add_edge(node.id, exit_node)
                previous_statements = None
            elif node.type == "try_statement":
                body_previous_statements = None
                except_previous_statements = None
                else_previous_statements = None
                finally_previous_statements = None
                for try_child_node in node.children:
                    if try_child_node.type == "block":
                        body_previous_statements = traverse_build_cfg(try_child_node, graph, node)
                    elif try_child_node.type == "except_clause":
                        graph.add_node(try_child_node.id, ast_node = try_child_node, text = try_child_node.text.decode())
                        if isinstance(body_previous_statements, list):
                            for p in body_previous_statements:
                                if p:
                                    graph.add_edge(p.id, try_child_node.id)
                        elif isinstance(body_previous_statements, Node):
                            graph.add_edge(body_previous_statements.id, try_child_node.id)
                        except_previous_statements = traverse_build_cfg(try_child_node, graph, try_child_node)
                    elif try_child_node.type == "else_clause":
                        graph.add_node(try_child_node.id, ast_node = try_child_node, text = try_child_node.text.decode())
                        if isinstance(body_previous_statements, list):
                            for p in body_previous_statements:
                                if p:
                                    graph.add_edge(p.id, try_child_node.id)
                        elif isinstance(body_previous_statements, Node):
                            graph.add_edge(body_previous_statements.id, try_child_node.id)
                        else_previous_statements = traverse_build_cfg(try_child_node, graph, try_child_node)
                    elif try_child_node.type == "finally_clause":
                        graph.add_node(try_child_node.id, ast_node = try_child_node, text = try_child_node.text.decode())
                        multiple_prev_stats = []
                        # body branch
                        if else_previous_statements:
                            if isinstance(else_previous_statements, list):
                                multiple_prev_stats.extend(else_previous_statements)
                            elif isinstance(else_previous_statements, Node):
                                multiple_prev_stats.append(else_previous_statements)
                        else:
                            if isinstance(body_previous_statements, list):
                                multiple_prev_stats.extend(body_previous_statements)
                            elif isinstance(body_previous_statements, Node):
                                multiple_prev_stats.append(body_previous_statements)
                        # exceptional branch
                        if isinstance(except_previous_statements, list):
                            multiple_prev_stats.extend(except_previous_statements)
                        elif isinstance(except_previous_statements, Node):
                            multiple_prev_stats.append(except_previous_statements)
                        if isinstance(multiple_prev_stats, list):
                            for p in multiple_prev_stats:
                                if p:
                                    graph.add_edge(p.id, try_child_node.id)
                        elif isinstance(multiple_prev_stats, Node):
                            graph.add_edge(multiple_prev_stats.id, try_child_node.id)
                        finally_previous_statements = traverse_build_cfg(try_child_node, graph, try_child_node)
                #
                previous_statements = []
                if finally_previous_statements:
                    if isinstance(finally_previous_statements, list):
                        previous_statements.extend(finally_previous_statements)
                    elif isinstance(finally_previous_statements, Node):
                        previous_statements.append(finally_previous_statements)
                else:
                    # body branch
                    if else_previous_statements:
                        if isinstance(else_previous_statements, list):
                            previous_statements.extend(else_previous_statements)
                        elif isinstance(else_previous_statements, Node):
                            previous_statements.append(else_previous_statements)
                    else:
                        if isinstance(body_previous_statements, list):
                            previous_statements.extend(body_previous_statements)
                        elif isinstance(body_previous_statements, Node):
                            previous_statements.append(body_previous_statements)
                    # exceptional branch
                    if isinstance(except_previous_statements, list):
                        previous_statements.extend(except_previous_statements)
                    elif isinstance(except_previous_statements, Node):
                        previous_statements.append(except_previous_statements)
            elif node.type == "with_statement":
                body = node.child_by_field_name("body")
                previous_statements = traverse_build_cfg(body, graph, node)
            else:
                previous_statements = node
        elif node.type == "function_definition":
            graph.add_node(node.id, ast_node = node, text = node.text.decode())
            if previous_statements is None:
                pass
            elif isinstance(previous_statements, list):
                for elem in previous_statements:
                    if elem:
                        graph.add_edge(elem.id, node.id, edge_type = "common")
            elif isinstance(previous_statements, Node):
                graph.add_edge(previous_statements.id, node.id, edge_type = "common")

            node.child_by_field_name("name")
            node.child_by_field_name("parameters")
            function_body_node = node.child_by_field_name("body")
            previous_statements = traverse_build_cfg(function_body_node, graph, node)
        else:
            for child in node.children:
                previous_statements = traverse_build_cfg(child, graph, previous_statements)
        return previous_statements

    previous_statements = traverse_build_cfg(root_node, graph, root_node)
    if isinstance(previous_statements, list):
        for pn in previous_statements:
            if pn:
                graph.add_edge(pn.id, exit_node, edge_type = "common")
    elif isinstance(previous_statements, Node):
        graph.add_edge(previous_statements.id, exit_node, edge_type = "common")
    return graph, root_node.id, exit_node


def identify_row_range(ast_node: Node):
    if ast_node is None:
        return -1, -1

    if ast_node.type in ["if_statement", "elif_clause", "while_statement"]:
        condition_node = ast_node.child_by_field_name("condition")
        start_row = condition_node.start_point.row
        end_row = condition_node.start_point.row
    elif ast_node.type == "for_statement":
        left_node = ast_node.child_by_field_name("left")
        right_node = ast_node.child_by_field_name("right")
        start_row = left_node.start_point.row
        end_row = right_node.end_point.row
    elif ast_node.type == "with_statement":
        child_0 = ast_node.child(0)
        child_1 = ast_node.child(1)
        child_2 = ast_node.child(2)
        if child_0 and child_0.type == "with" and child_1 and child_1.type == "with_clause":
            start_row, end_row = child_0.start_point.row, child_1.end_point.row
        elif child_0 and child_0.type == "async" and child_1 and child_1.type == "with" and child_2 and child_2.type == "with_clause":
            start_row, end_row = child_0.start_point.row, child_2.end_point.row
        else: 
            print("[Warning] Unexpected with_statement structure")
            print(ast_node.text.decode())
            print(child_1.text.decode(), child_1.type)
    elif ast_node.type in ["try_statement", "else_clause", "finally_clause", "except_clause"]:
        sp = ast_node.start_point
        start_row, end_row = sp.row, sp.row
    elif ast_node.type == "function_definition":
        start_row = ast_node.start_point.row
        parameter_node = ast_node.child_by_field_name("parameters")
        if parameter_node:
            end_row = parameter_node.end_point.row
    else:
        sp, ep = ast_node.start_point, ast_node.end_point
        start_row, end_row = sp.row, ep.row
    return start_row, end_row


def identify_def_or_use_variable(node: Node):
    """Find all used varialbes in the given node."""
    def_var_set = set()
    use_var_set = set()

    if node.type == "assignment":
        left_node = node.child_by_field_name("left")
        right_node = node.child_by_field_name("right")
        if left_node and left_node.type == "identifier":
            identifier_name = left_node.text.decode()
            def_var_set.add(identifier_name)
        if right_node:    
            right_def_set, right_use_set = identify_def_or_use_variable(right_node)
            if right_use_set:
                use_var_set.update(right_use_set)
            if right_def_set:
                def_var_set.update(def_var_set)
        return def_var_set, use_var_set

    if node.type == "augmented_assignment":
        left_node = node.child_by_field_name("left")
        right_node = node.child_by_field_name("right")
        if left_node and left_node.type == "identifier":
            identifier_name = left_node.text.decode()
            def_var_set.add(identifier_name)
            use_var_set.add(identifier_name)
        if right_node:    
            right_def_set, right_use_set = identify_def_or_use_variable(right_node)
            if right_use_set:
                use_var_set.update(right_use_set)
            if right_def_set:
                def_var_set.update(def_var_set)
        return def_var_set, use_var_set
    
    if node.type in ["if_statement", "elif_clause", "while_statement"]:
        condition_node = node.child_by_field_name("condition")
        return identify_def_or_use_variable(condition_node)
    
    if node.type == "for_statement":
        left_node = node.child_by_field_name("left")
        right_node = node.child_by_field_name("right")
        if left_node and left_node.type == "identifier":
            id_name = left_node.text.decode()
            def_var_set.add(id_name)
        right_ds, right_us = identify_def_or_use_variable(right_node)
        def_var_set.update(right_ds)
        use_var_set.update(right_us)
        return def_var_set, use_var_set
    
    if node.type == "with_statement":
        with_clause = node.child(1)
        if with_clause and with_clause.type == "with_clause":
            pds, pus = identify_def_or_use_variable(with_clause)
            def_var_set.update(pds)
            use_var_set.update(pus)
        return def_var_set, use_var_set

    if node.type in ["try_statement", "else_clause", "finally_clause", "except_clause"]:
        return  def_var_set, use_var_set

    if node.type == "as_pattern":
        left_node = node.child(0)
        pds, pus = identify_def_or_use_variable(left_node)
        def_var_set.update(pds)
        use_var_set.update(pus)

        alias_node = node.child(2)
        # print("[DEBUG]",node.text.decode())
        iden_node = alias_node.child(0)
        if iden_node and iden_node.type == "identifier":
            def_var_set.add(iden_node.text.decode())
        return def_var_set, use_var_set
    
    if node.type == "function_definition":
        parameter_node = node.child_by_field_name("parameters")
        if parameter_node and parameter_node.type == "parameters":
            for xnode in parameter_node.children:
                if xnode.type == "identifier":
                    def_var_set.add(xnode.text.decode())
        return def_var_set, use_var_set


    if node.type == "identifier":
        name = node.text.decode()
        use_var_set.add(name)

    for child in node.children:
        pds, pus = identify_def_or_use_variable(child)
        def_var_set.update(pds)
        use_var_set.update(pus)

    return def_var_set, use_var_set


def extract_definition_use_statements_and_varible_dicts(cfg: nx.DiGraph, language: str):
    """Extract 4 variable and statements dictionary."""
    var2def_stat = {}
    var2use_stat = {}
    def_stat2var = {}
    use_stat2var = {}

    for node in cfg.nodes:
        text = cfg.nodes[node]["text"]
        ast_node: Node = cfg.nodes[node]["ast_node"]
        if text in ["Entry", "Exit"]:
            continue
        if language == "python":
            def_var_set, use_var_set = identify_def_or_use_variable(ast_node)
        elif language == "c":
            def_var_set, use_var_set = identify_def_or_use_variable_c(ast_node)
        elif language == "cpp":
            def_var_set, use_var_set = identify_def_or_use_variable_cpp(ast_node)
        elif language == "javascript":
            def_var_set, use_var_set = identify_def_or_use_variable_javascript(ast_node)
        else:
            raise ValueError(f"unsupported PDG language: {language}")
        if def_var_set:
            def_stat2var[node] = def_var_set
            for var_item in def_var_set:
                var2def_stat.setdefault(var_item, set()).add(node)
        if use_var_set:
            use_stat2var[node] = use_var_set
            for var_item in use_var_set:
                var2use_stat.setdefault(var_item, set()).add(node)
    return var2def_stat, var2use_stat, def_stat2var, use_stat2var


def perform_reaching_definition_analysis(cfg: nx.DiGraph, var2def_stat: Dict[str, set]):
    """Data-Flow Analysis of RDA, aimed to finding the working area of every def statement."""
    # build GEN and KILL: [def, set(def)]
    GEN = {}
    KILL = {}
    for var, def_statement_set in var2def_stat.items():
        for def_s in def_statement_set:
            GEN[def_s] = {def_s}
            KILL[def_s] = def_statement_set
    
    # init the OUT
    out_set_dict = {node: set() for node in cfg.nodes}

    # iterate the cfg
    change = True
    while change:
        change = False
        for node in nx.dfs_preorder_nodes(cfg):
            in_set = set()
            for pre_node in cfg.predecessors(node):
                in_set.update(out_set_dict[pre_node])
            
            # GEN[B] union (IN[B] - KILL[B])
            out_set = GEN.get(node, set()) | (in_set - KILL.get(node, set()))
            if out_set != out_set_dict[node]:
                change = True
                out_set_dict[node] = out_set
    return out_set_dict


def build_data_dependence(cfg: nx.DiGraph, use_stat2var_set: Dict[str, set], def_stat2var_set: Dict[str, set],
                  var2use_stat: Dict[str, set], var2def_stat: Dict[str, set],
                  rda_out_set_dict: Dict[str, set]):
    """Extract all the def use pairs for constructing data dependence graph"""
    def_use_pair_list = []
    for node in cfg.nodes:
        if node not in use_stat2var_set:
            continue

        # get IN def set
        available_def_set = set()
        for prev_node in cfg.predecessors(node):
            available_def_set.update(rda_out_set_dict[prev_node])

        use_var_set = use_stat2var_set[node]
        for var in use_var_set:
            # print(use_var_set)
            possible_def_statements = var2def_stat.get(var, set())
            concrete_def_statements = available_def_set & possible_def_statements
            for ds in concrete_def_statements:
                def_use_pair_list.append((ds, node, var))
    return def_use_pair_list
        

# The following code is to build Control Dependence Graph
def perform_post_dominators(cfg: nx.DiGraph):
    """
    Compute the post dominator analysis, backward analysis.
    """
    pdom_dict = {node: set(cfg.nodes) for node in cfg.nodes}
    change = True
    while change:
        change = False
        for node in reversed(list(nx.topological_sort(cfg))):
            # pdom = {n} union (intersection of sucessor's podom)
            new_pdom = {node} | set.intersection(
                *[pdom_dict[suc] for suc in cfg.successors(node)]
            )

            if new_pdom != pdom_dict[node]:
                pdom_dict[node] = new_pdom
                change = True
    return pdom_dict


def perform_immediate_post_dominator(cfg: nx.DiGraph, exit_node: str):
    cfg_reverse = cfg.reverse(copy=False)
    order = list(nx.dfs_postorder_nodes(cfg_reverse, exit_node))
    dfn2idx = {n: i for i, n in enumerate(order)}
    order.pop()
    order.reverse()

    ipdom = {exit_node: exit_node}
    
    def find_nearest_common_ancestor(u, v):
        while u != v:
            while dfn2idx[u] < dfn2idx[v]:
                u = ipdom[u]
            while dfn2idx[u] > dfn2idx[v]:
                v = ipdom[v]
        return u

    change = True
    while change:
        change = False
        for u in order:
            new_ipdom = reduce(find_nearest_common_ancestor, (v for v in cfg_reverse.predecessors(u) if v in ipdom))
            if u not in ipdom or new_ipdom != ipdom[u]:
                change = True
                ipdom[u] = new_ipdom

    return ipdom


def compute_post_dominance_frontiers(cfg: nx.DiGraph, ipdom: Dict[str, str]) -> Dict[str, Set[str]]:
    # Initialize empty frontiers for all nodes in ipdom
    pdf = {u: set() for u in ipdom}
    
    # For each node that has multiple predecessors in the original CFG
    # (which means multiple successors in the reversed graph)
    cfg_reverse = cfg.reverse(copy=False)
    for u in ipdom:
        if len(cfg_reverse.pred[u]) >= 2:  # Node has multiple successors in original CFG
            # For each predecessor in reversed graph (successor in original)
            for v in cfg_reverse.pred[u]:
                if v in ipdom:
                    runner = v
                    # Walk up the post-dominator tree until we reach
                    # the immediate post-dominator of u
                    while runner != ipdom[u]:
                        pdf[runner].add(u)
                        runner = ipdom[runner]
    return pdf


def build_control_dependence(post_dominace_frontier: Dict[str, set]):
    control_edge_list = []
    for node, frontier in post_dominace_frontier.items():
        for frontier_node in frontier:
            control_edge_list.append((frontier_node, node, "[CONTROL]"))
    return control_edge_list


def build_program_dependence_graph(tree: Tree, language: str = "python"):
    if language == "python":
        cfg, entry_node, exit_node = build_control_flow_graph(tree)
    elif language == "c":
        cfg, entry_node, exit_node = build_control_flow_graph_c(tree)
    elif language == "cpp":
        cfg, entry_node, exit_node = build_control_flow_graph_cpp(tree)
    elif language == "javascript":
        cfg, entry_node, exit_node = build_control_flow_graph_javascript(tree)
    else:
        raise ValueError(f"unsupported PDG language: {language}")
    # Data Dependence
    var2def_stat, var2use_stat, def_stat2var, use_stat2var = extract_definition_use_statements_and_varible_dicts(cfg, language)
    out_set_def_dict = perform_reaching_definition_analysis(cfg, var2def_stat)
    data_edge_list = build_data_dependence(cfg, use_stat2var, def_stat2var, var2use_stat, var2def_stat, out_set_def_dict)
    # print(data_edge_list)
    # Control Dependence
    ipdom = perform_immediate_post_dominator(cfg, exit_node)
    pdf = compute_post_dominance_frontiers(cfg, ipdom)
    control_edge_list = build_control_dependence(pdf)

    # Program Dependence Graph
    pdg = nx.DiGraph()
    pdg.add_nodes_from(cfg.nodes(data=True))
    for u, v, text in data_edge_list:
        pdg.add_edge(u, v, category = f'data:{text}')

    for u, v, text in control_edge_list:
        pdg.add_edge(u, v, category = "control")
    
    return pdg


def backward_slice(pdg: nx.DiGraph, criteria: Set, hop: int):
    """
    Perform backward program slicing.
    
    Args:
        pdg: Program dependence graph
        criteria: Set of starting nodes
        hop: Maximum number of hops to traverse (use -1 for unlimited)
    
    Returns:
        Subgraph containing the backward slice
    """
    sliced_nodes = set(criteria)
    all_nodes = set(pdg.nodes)
    if sliced_nodes - all_nodes:
        raise ValueError("Input contains invalid nodes")

    queue = set(criteria)
    cur_hop = hop
    
    while queue and (cur_hop != 0):
        if hop > 0:
            cur_hop -= 1
        next_queue = set()
        
        for vn in queue:
            # Only traverse predecessors for backward slice
            for pvn in pdg.predecessors(vn):
                if pvn not in sliced_nodes:
                    sliced_nodes.add(pvn)
                    next_queue.add(pvn)
        
        queue = next_queue
    
    return pdg.subgraph(sliced_nodes)


def forward_slice(pdg: nx.DiGraph, criteria: Set, hop: int):
    """
    Perform forward program slicing.
    
    Args:
        pdg: Program dependence graph
        criteria: Set of starting nodes
        hop: Maximum number of hops to traverse (use -1 for unlimited)
    
    Returns:
        Subgraph containing the forward slice
    """
    sliced_nodes = set(criteria)
    all_nodes = set(pdg.nodes)
    if sliced_nodes - all_nodes:
        raise ValueError("Input contains invalid nodes")

    queue = set(criteria)
    cur_hop = hop
    
    while queue and (cur_hop != 0):
        if hop > 0:
            cur_hop -= 1
        next_queue = set()
        
        for vn in queue:
            # Only traverse successors for forward slice
            for svn in pdg.successors(vn):
                if svn not in sliced_nodes:
                    sliced_nodes.add(svn)
                    next_queue.add(svn)
        
        queue = next_queue
    
    return pdg.subgraph(sliced_nodes)


def perform_slicing(pdg: nx.DiGraph, criteria: Set, hop: int, direction: str = "both"):
    """
    Entrance for the program slicing.
    
    Args:
        pdg: Program dependence graph
        criteria: Set of starting nodes
        hop: Maximum number of hops to traverse (use -1 for unlimited)
        direction: Slicing direction, one of "forward", "backward", or "both"
    
    Returns:
        Subgraph containing the slice
    """
    if direction == "forward":
        return forward_slice(pdg, criteria, hop)
    elif direction == "backward":
        return backward_slice(pdg, criteria, hop)
    elif direction == "both":
        # Perform both forward and backward slicing and combine results
        forward_nodes = set(forward_slice(pdg, criteria, hop).nodes())
        backward_nodes = set(backward_slice(pdg, criteria, hop).nodes())
        combined_nodes = forward_nodes.union(backward_nodes)
        return pdg.subgraph(combined_nodes)
    else:
        raise ValueError("direction must be one of: 'forward', 'backward', or 'both'")


def project_lineid_into_node(pdg: nx.DiGraph, line_id: int) -> List[str]:
    """Given a line id, find which node containing this line. The node can be multiple sometimes."""
    result_node = []
    for node in pdg:
        ast_node = pdg.nodes[node]["ast_node"]
        if ast_node:
            # Get start and end positions from tree-sitter node
            start_row, end_row = identify_row_range(ast_node)            
            # Check if line_id falls within this node's range
            if start_row <= line_id <= end_row:
                result_node.append(node)
    return result_node


def mapping_two_version_diffs(before_code: str, after_code: str):
    d = Differ()
    before_code = before_code.splitlines(True) # TODO, but why?
    after_code = after_code.splitlines(True)
    result = d.compare(before_code, after_code)
    #
    before_line_id, after_line_id = -1, -1
    before_modified_lines = []
    after_modified_lines = []
    bl_al_mapping = []

    for r in result:
        tag = r[0]
        if tag == "+":
            after_line_id += 1
            after_modified_lines.append(after_line_id)
        elif tag == "-":
            before_line_id += 1
            before_modified_lines.append(before_line_id)
        elif tag == "?":
            pass
        elif tag == " ":
            before_line_id += 1
            after_line_id += 1
            bl_al_mapping.append((before_line_id, after_line_id))
        else:
            raise KeyError("Unseen tag symbol.")
    return before_modified_lines, after_modified_lines, bl_al_mapping


def from_subgraph_to_lineids(subgraph: nx.DiGraph, language):
    """transform the sliced subgraph into corresponding lines."""
    all_line_ids = []
    for n in subgraph:
        ast_node = subgraph.nodes[n]["ast_node"]
        if language == "python":
            start_row, end_row = identify_row_range(ast_node)
        elif language == "c":
            start_row, end_row = identify_row_range_c(ast_node)
        for l in range(start_row, end_row + 1):
            all_line_ids.append(l)
    all_line_ids = sorted(set(all_line_ids))
    return all_line_ids


def find_func_def_lines_py(node: Node):
    lines = []
    if node.type == "function_definition":
        start_row = node.start_point.row
        end_row = node.child_by_field_name("parameters").end_point.row
        for i in range(start_row, end_row + 1):
            lines.append(i)
        return lines
    for child in node.children:
        lines.extend(
            find_func_def_lines_py(child)
        )
    return lines


def merge_two_version_lines(before_line_ids, after_line_ids, bl_al_mapping):
    bl2al = {before_line: after_line for before_line, after_line in bl_al_mapping}
    al2bl = {after_line: before_line for before_line, after_line in bl_al_mapping}
    
    new_after_lines_set = set(after_line_ids)
    # make up after line
    for x in before_line_ids:
        if x in bl2al:
            new_after_lines_set.add(bl2al[x])

    new_before_lines_set = set(before_line_ids)
    for x in after_line_ids:
        if x in al2bl:
            new_before_lines_set.add(al2bl[x])
    return sorted(new_before_lines_set), sorted(new_after_lines_set)


def lines_to_code(lines: List[int], code: str):
    codes = code.splitlines()
    sliced_code = "\n".join(
        [codes[x] for x in lines]
    )
    return sliced_code


def main_py(vulnerable_code: str, secure_code: str):
    # Initialize the AST and CFG
    parser = Parser(Language(tspy.language()))
    vuln_tree = parser.parse(vulnerable_code.encode("utf-8"))
    sec_tree = parser.parse(secure_code.encode("utf-8"))
    vuln_pdg = build_program_dependence_graph(vuln_tree, "python")
    sec_pdg = build_program_dependence_graph(sec_tree, "python")

    # Identify slicing criteria
    before_modified_lines, after_modified_lines, bl_al_mapping = mapping_two_version_diffs(vulnerable_code, secure_code)
    vuln_slicing_criteria = {x for bml_id in before_modified_lines 
        for x in project_lineid_into_node(vuln_pdg, bml_id)}
    sec_slicing_criteria = {x for aml_id in  after_modified_lines
                                for x in project_lineid_into_node(sec_pdg, aml_id)}

    vuln_subgraph = perform_slicing(vuln_pdg, vuln_slicing_criteria, 2, "both")
    sec_subgraph = perform_slicing(sec_pdg, sec_slicing_criteria, 2, "both")

    vuln_lines = from_subgraph_to_lineids(vuln_subgraph, "python")
    sec_lines = from_subgraph_to_lineids(sec_subgraph, "python")
    

    vuln_lines, sec_lines = merge_two_version_lines(vuln_lines, sec_lines, bl_al_mapping)
    vuln_sliced_code = lines_to_code(vuln_lines, vulnerable_code)
    sec_sliced_code = lines_to_code(sec_lines, secure_code)
    return vuln_sliced_code, sec_sliced_code

def identify_row_range_c(ast_node: Node):
    """Identify the line range for C AST nodes"""
    if ast_node is None:
        return -1, -1

    if ast_node.type in ["if_statement", "while_statement", "do_statement",
                         "switch_statement"]:
        condition = ast_node.child_by_field_name("condition")
        if condition:
            start_row = condition.start_point[0]
            end_row = condition.end_point[0]
        else:
            # start_row = ast_node.start_point[0]
            # end_row = ast_node.start_point[0]
            print("Wrong situation.")
    elif ast_node.type == "for_statement":
        start_row = ast_node.start_point.row
        for child in ast_node.children:
            if child.text.decode() == ")":
                end_row = child.end_point.row
                break
    elif ast_node.type == "case_statement":
        value = ast_node.child_by_field_name("value")
        start_row = ast_node.start_point[0]
        if value:
            end_row = value.end_point[0]
        else:
            default_node = ast_node.child(0)
            if default_node and default_node.type == "default":
                end_row = default_node.end_point.row
            
    elif ast_node.type == "function_definition":
        declarator = ast_node.child_by_field_name("declarator")
        start_row = ast_node.start_point[0]
        end_row = declarator.end_point[0] if declarator else start_row
    elif ast_node.type == "else_clause":
        sp = ast_node.start_point
        start_row, end_row = sp.row, sp.row
    else:
        start_row = ast_node.start_point[0]
        end_row = ast_node.end_point[0]
    return start_row, end_row


def find_identifier_c(node: Node):
    id_set = set()
    if node.type == "identifier":
        id_set.add(node.text.decode())
    for child in node.children:
        new_id_set = find_identifier_c(child)
        id_set.update(new_id_set)
    return id_set

def identify_def_or_use_variable_c(node: Node):
    """Find all defined and used variables in the given C AST node."""
    def_var_set = set()
    use_var_set = set()

    if node.type == "declaration":
        declarator = node.child_by_field_name("declarator")
        if declarator:
            if declarator.type == "identifier":
                def_var_set.add(declarator.text.decode())
            elif declarator.type == "init_declarator":
                # 
                id_node = declarator.child_by_field_name("declarator")
                if id_node:
                    new_ids = find_identifier_c(id_node)
                    def_var_set.update(new_ids)

                value = declarator.child_by_field_name("value")
                if value:
                    def_set, use_set = identify_def_or_use_variable_c(value)
                    def_var_set.update(def_set)
                    use_var_set.update(use_set)
            elif "declarator" in declarator.type:
                new_ids = find_identifier_c(declarator)
                def_var_set.update(new_ids)
        return def_var_set, use_var_set
    elif node.type == "assignment_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        
        if left and left.type == "identifier":
            def_var_set.add(left.text.decode())
        elif left and left.type == "field_expression":
            def_var_set.add(left.text.decode())
            argument = left.child_by_field_name("argument")
            if argument and argument.type == "identifier":
                use_var_set.add(argument.text.decode())
        elif left:
            _, left_uses = identify_def_or_use_variable_c(left)
            use_var_set.update(left_uses)
            
        if right:
            _, right_uses = identify_def_or_use_variable_c(right)
            use_var_set.update(right_uses)
        return def_var_set, use_var_set
    elif node.type in ["parameter_declaration"]:
        # print(node.type)
        declarator = node.child_by_field_name("declarator")
        if declarator:
            def_var_set.update(find_identifier_c(declarator))
        return def_var_set, use_var_set
    elif node.type == "function_definition":
        declarator = node.child_by_field_name("declarator")
        if declarator and declarator.type == "identifier":
            def_var_set.add(declarator.text.decode())
    elif node.type in ["if_statement", "while_statement", "do_statement", "switch_statement"]:
        condition_node = node.child_by_field_name("condition")
        return identify_def_or_use_variable_c(condition_node)
    elif node.type == "for_statement":
        for field in ["initializer", "condition", "update"]:
            field_node = node.child_by_field_name(field)
            if field_node:
                ds, vs = identify_def_or_use_variable_c(field_node)
                def_var_set |= ds
                use_var_set |= vs
        return def_var_set, use_var_set
    elif node.type == "else_clause":
        return def_var_set, use_var_set
    elif node.type in ["identifier", "field_expression"]:
        use_var_set.add(node.text.decode())
        # return def_var_set, use_var_set

    # Recursively process child nodes
    for child in node.children:
        child_defs, child_uses = identify_def_or_use_variable_c(child)
        def_var_set.update(child_defs)
        use_var_set.update(child_uses)

    return def_var_set, use_var_set


def _cpp_declarator_names(node: Node) -> set[str]:
    """Return binding names from a C++ declarator without treating type names as values."""
    if node is None:
        return set()
    if node.type == "identifier":
        return {node.text.decode()}
    names: set[str] = set()
    declarator = node.child_by_field_name("declarator")
    if declarator is not None and declarator != node:
        names.update(_cpp_declarator_names(declarator))
        return names
    if node.type == "structured_binding_declarator":
        for child in node.named_children:
            names.update(_cpp_declarator_names(child))
        return names
    for child in node.named_children:
        if child.type not in {"parameter_list", "argument_list", "initializer_list"}:
            names.update(_cpp_declarator_names(child))
    return names


def _cpp_lvalue_names(node: Node) -> tuple[set[str], set[str]]:
    """Return (definitions, object uses) for a C++ assignment target."""
    if node is None:
        return set(), set()
    if node.type == "identifier":
        name = node.text.decode()
        return {name}, set()
    if node.type in {"field_expression", "subscript_expression"}:
        argument = node.child_by_field_name("argument")
        object_defs, object_uses = identify_def_or_use_variable_cpp(argument) if argument else (set(), set())
        return {node.text.decode()}, object_defs | object_uses
    _, uses = identify_def_or_use_variable_cpp(node)
    return set(), uses


def identify_def_or_use_variable_cpp(node: Node):
    """Extract conservative C++ definitions and uses for the PDG dataflow pass."""
    if node is None:
        return set(), set()
    defs: set[str] = set()
    uses: set[str] = set()

    if node.type in {"declaration", "field_declaration"}:
        declarator = node.child_by_field_name("declarator")
        defs.update(_cpp_declarator_names(declarator))
        value = declarator.child_by_field_name("value") if declarator else None
        if value is not None:
            _, value_uses = identify_def_or_use_variable_cpp(value)
            uses.update(value_uses)
        return defs, uses
    if node.type == "parameter_declaration":
        return _cpp_declarator_names(node.child_by_field_name("declarator")), set()
    if node.type == "function_definition":
        declarator = node.child_by_field_name("declarator")
        defs.update(_cpp_declarator_names(declarator.child_by_field_name("declarator") if declarator else None))
        if declarator:
            for parameter in declarator.children_by_field_name("parameters"):
                for child in parameter.named_children:
                    child_defs, _ = identify_def_or_use_variable_cpp(child)
                    defs.update(child_defs)
        return defs, uses
    if node.type == "assignment_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        left_defs, left_uses = _cpp_lvalue_names(left)
        _, right_uses = identify_def_or_use_variable_cpp(right)
        return left_defs, left_uses | right_uses
    if node.type == "update_expression":
        argument = node.child_by_field_name("argument")
        update_defs, update_uses = _cpp_lvalue_names(argument)
        return update_defs, update_uses | update_defs
    if node.type in {"if_statement", "while_statement", "do_statement", "switch_statement"}:
        return identify_def_or_use_variable_cpp(node.child_by_field_name("condition"))
    if node.type == "for_statement":
        for field in ("initializer", "condition", "update"):
            child_defs, child_uses = identify_def_or_use_variable_cpp(node.child_by_field_name(field))
            defs.update(child_defs)
            uses.update(child_uses)
        return defs, uses
    if node.type == "identifier":
        return set(), {node.text.decode()}
    if node.type in {"type_identifier", "namespace_identifier", "field_identifier", "primitive_type"}:
        return defs, uses

    for child in node.named_children:
        child_defs, child_uses = identify_def_or_use_variable_cpp(child)
        defs.update(child_defs)
        uses.update(child_uses)
    return defs, uses


def build_control_flow_graph_cpp(tree: Tree):
    """Build a native-C++ CFG using the shared C-family statement topology.

    Tree-sitter C++ exposes the same control-flow field names as C for functions,
    blocks, branches, loops, switch cases, and returns. C++-specific dataflow is
    handled separately by ``identify_def_or_use_variable_cpp``.
    """
    return build_control_flow_graph_c(tree)


def identify_row_range_cpp(ast_node: Node):
    """Map native C++ statement nodes to source rows for slice reporting."""
    return identify_row_range_c(ast_node)


def project_lineid_into_node_cpp(pdg: nx.DiGraph, line_id: int) -> List[str]:
    result = []
    for node in pdg:
        ast_node = pdg.nodes[node]["ast_node"]
        if ast_node:
            start_row, end_row = identify_row_range_cpp(ast_node)
            if start_row <= line_id <= end_row:
                result.append(node)
    return result


def from_subgraph_to_lineids_cpp(subgraph: nx.DiGraph, language: str = "cpp"):
    all_line_ids = []
    for node in subgraph:
        ast_node = subgraph.nodes[node]["ast_node"]
        start_row, end_row = identify_row_range_cpp(ast_node)
        for line in range(start_row, end_row + 1):
            all_line_ids.append(line)
    return sorted(set(all_line_ids))


def _js_binding_names(node: Node) -> set[str]:
    """Return bindings introduced by a JavaScript declaration or pattern."""
    if node is None:
        return set()
    if node.type == "identifier":
        return {node.text.decode()}
    if node.type == "shorthand_property_identifier_pattern":
        return {node.text.decode()}
    if node.type in {"rest_pattern", "assignment_pattern", "object_assignment_pattern"}:
        return _js_binding_names(node.child_by_field_name("left") or node.named_children[0])
    if node.type == "pair_pattern":
        return _js_binding_names(node.child_by_field_name("value"))
    names: set[str] = set()
    for child in node.named_children:
        names.update(_js_binding_names(child))
    return names


def _js_lvalue_names(node: Node) -> tuple[set[str], set[str]]:
    """Return definitions and object uses for a JavaScript assignment target."""
    if node is None:
        return set(), set()
    if node.type == "identifier":
        return {node.text.decode()}, set()
    if node.type in {"member_expression", "subscript_expression"}:
        object_node = node.child_by_field_name("object")
        _, object_uses = identify_def_or_use_variable_javascript(object_node)
        return {node.text.decode()}, object_uses
    return _js_binding_names(node), set()


def identify_def_or_use_variable_javascript(node: Node):
    """Extract conservative JavaScript definitions and uses for PDG dataflow."""
    if node is None:
        return set(), set()
    defs: set[str] = set()
    uses: set[str] = set()

    if node.type in {"lexical_declaration", "variable_declaration"}:
        for declarator in node.named_children:
            if declarator.type != "variable_declarator":
                continue
            defs.update(_js_binding_names(declarator.child_by_field_name("name")))
            _, value_uses = identify_def_or_use_variable_javascript(declarator.child_by_field_name("value"))
            uses.update(value_uses)
        return defs, uses
    if node.type == "variable_declarator":
        defs.update(_js_binding_names(node.child_by_field_name("name")))
        _, value_uses = identify_def_or_use_variable_javascript(node.child_by_field_name("value"))
        return defs, value_uses
    if node.type == "function_declaration":
        name = node.child_by_field_name("name")
        if name is not None:
            defs.add(name.text.decode())
        parameters = node.child_by_field_name("parameters")
        if parameters is not None:
            for parameter in parameters.named_children:
                defs.update(_js_binding_names(parameter))
        return defs, uses
    if node.type in {"function", "function_expression", "arrow_function"}:
        parameters = node.child_by_field_name("parameters")
        if parameters is not None:
            for parameter in parameters.named_children:
                defs.update(_js_binding_names(parameter))
        return defs, uses
    if node.type == "assignment_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        left_defs, left_uses = _js_lvalue_names(left)
        _, right_uses = identify_def_or_use_variable_javascript(right)
        return left_defs, left_uses | right_uses
    if node.type == "augmented_assignment_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        left_defs, left_uses = _js_lvalue_names(left)
        _, right_uses = identify_def_or_use_variable_javascript(right)
        return left_defs, left_defs | left_uses | right_uses
    if node.type == "update_expression":
        argument = node.child_by_field_name("argument") or (node.named_children[0] if node.named_children else None)
        update_defs, update_uses = _js_lvalue_names(argument)
        return update_defs, update_defs | update_uses
    if node.type in {"if_statement", "while_statement", "do_statement", "switch_statement"}:
        return identify_def_or_use_variable_javascript(node.child_by_field_name("condition") or node.child_by_field_name("value"))
    if node.type in {"for_statement", "for_in_statement"}:
        for field in ("initializer", "left", "right", "condition", "update"):
            child_defs, child_uses = identify_def_or_use_variable_javascript(node.child_by_field_name(field))
            defs.update(child_defs)
            uses.update(child_uses)
        return defs, uses
    if node.type == "catch_clause":
        defs.update(_js_binding_names(node.child_by_field_name("parameter")))
        return defs, uses
    if node.type == "identifier":
        return set(), {node.text.decode()}
    if node.type in {"property_identifier", "private_property_identifier", "comment"}:
        return defs, uses

    for child in node.named_children:
        child_defs, child_uses = identify_def_or_use_variable_javascript(child)
        defs.update(child_defs)
        uses.update(child_uses)
    return defs, uses


def build_control_flow_graph_javascript(tree: Tree):
    """Build a conservative statement-level CFG for native JavaScript syntax."""
    graph = nx.DiGraph()
    root = tree.root_node
    graph.add_node(root.id, ast_node=None, text="Entry")
    exit_node = id("JavaScriptExitNode")
    graph.add_node(exit_node, ast_node=None, text="Exit")

    statement_types = {
        "lexical_declaration", "variable_declaration", "expression_statement",
        "if_statement", "while_statement", "do_statement", "for_statement",
        "for_in_statement", "switch_statement", "switch_case", "switch_default",
        "return_statement", "throw_statement", "break_statement", "continue_statement",
        "try_statement", "debugger_statement", "empty_statement",
    }

    def link(previous, current):
        if previous is None:
            return
        if isinstance(previous, list):
            for item in previous:
                link(item, current)
        elif isinstance(previous, Node):
            graph.add_edge(previous.id, current.id, edge_type="common")

    def traverse(node: Node, previous):
        if node is None:
            return previous
        if node.type in {"program", "statement_block", "class_body", "switch_body"}:
            current = previous
            for child in node.named_children:
                current = traverse(child, current)
            return current
        if node.type in {"function_declaration", "method_definition"}:
            graph.add_node(node.id, ast_node=node, text=node.text.decode())
            link(previous, node)
            body = node.child_by_field_name("body")
            traverse(body, node)
            return node
        if node.type in statement_types:
            graph.add_node(node.id, ast_node=node, text=node.text.decode())
            link(previous, node)
            if node.type == "if_statement":
                exits = []
                consequence = traverse(node.child_by_field_name("consequence"), node)
                if consequence is not None:
                    exits.extend(consequence if isinstance(consequence, list) else [consequence])
                alternative = node.child_by_field_name("alternative")
                if alternative is not None:
                    alternative_exit = traverse(alternative, node)
                    if alternative_exit is not None:
                        exits.extend(alternative_exit if isinstance(alternative_exit, list) else [alternative_exit])
                else:
                    exits.append(node)
                return exits
            if node.type in {"while_statement", "do_statement", "for_statement", "for_in_statement"}:
                body_exit = traverse(node.child_by_field_name("body"), node)
                if isinstance(body_exit, list):
                    for item in body_exit:
                        link(item, node)
                else:
                    link(body_exit, node)
                return node
            if node.type == "switch_statement":
                body = node.child_by_field_name("body")
                exits = []
                if body is not None:
                    for case in body.named_children:
                        case_exit = traverse(case, node)
                        if case_exit is not None:
                            exits.extend(case_exit if isinstance(case_exit, list) else [case_exit])
                return exits or node
            if node.type in {"switch_case", "switch_default"}:
                current = node
                for child in node.named_children:
                    current = traverse(child, current)
                return current
            if node.type == "try_statement":
                exits = []
                for field in ("body", "handler"):
                    branch = traverse(node.child_by_field_name(field), node)
                    if branch is not None:
                        exits.extend(branch if isinstance(branch, list) else [branch])
                finalizer = node.child_by_field_name("finalizer")
                if finalizer is not None:
                    return traverse(finalizer, exits or node)
                return exits or node
            if node.type in {"return_statement", "throw_statement"}:
                graph.add_edge(node.id, exit_node, edge_type="common")
                return None
            return node
        if node.type in {"else_clause", "catch_clause", "finally_clause", "export_statement"}:
            body = node.child_by_field_name("body")
            if body is not None:
                return traverse(body, previous)
        current = previous
        for child in node.named_children:
            current = traverse(child, current)
        return current

    final = traverse(root, root)
    if isinstance(final, list):
        for node in final:
            link(node, type("Exit", (), {"id": exit_node})())
    elif isinstance(final, Node):
        graph.add_edge(final.id, exit_node, edge_type="common")
    return graph, root.id, exit_node


def identify_row_range_javascript(ast_node: Node):
    if ast_node is None:
        return -1, -1
    if ast_node.type in {"if_statement", "while_statement", "do_statement", "for_statement", "for_in_statement", "switch_statement"}:
        condition = ast_node.child_by_field_name("condition") or ast_node.child_by_field_name("value")
        if condition is not None:
            return condition.start_point.row, condition.end_point.row
    return ast_node.start_point.row, ast_node.end_point.row


def project_lineid_into_node_javascript(pdg: nx.DiGraph, line_id: int) -> List[str]:
    result = []
    for node in pdg:
        ast_node = pdg.nodes[node]["ast_node"]
        if ast_node:
            start_row, end_row = identify_row_range_javascript(ast_node)
            if start_row <= line_id <= end_row:
                result.append(node)
    return result


def from_subgraph_to_lineids_javascript(subgraph: nx.DiGraph, language: str = "javascript"):
    lines = []
    for node in subgraph:
        ast_node = subgraph.nodes[node]["ast_node"]
        start_row, end_row = identify_row_range_javascript(ast_node)
        lines.extend(range(start_row, end_row + 1))
    return sorted(set(lines))


def build_control_flow_graph_c(tree: Tree):
    """Build control flow graph for C code"""
    graph = nx.DiGraph()
    root_node = tree.root_node
    graph.add_node(root_node.id, ast_node=None, text="Entry")
    exit_node = id("ExitNode")
    graph.add_node(exit_node, ast_node=None, text="Exit")

    def traverse_build_cfg(node: Node, graph: nx.DiGraph, previous_statements: Union[Node, List[Node]]):
        if node.type == "compound_statement":
            current_prev = previous_statements
            for child in node.children:
                if child.type == "{":
                    left_pa = child.start_point.row
                elif child.type == "}":
                    right_pa = child.start_point.row

            for child in node.children:
                if child.type != "{" and child.type != "}":
                    current_prev = traverse_build_cfg(child, graph, current_prev)
            
            return current_prev

        if "statement" in node.type or "declaration" == node.type:
            graph.add_node(node.id, ast_node=node, text=node.text.decode())
            if previous_statements is None:
                pass
            elif isinstance(previous_statements, list):
                for elem in previous_statements:
                    if elem:
                        graph.add_edge(elem.id, node.id, edge_type="common")
            elif isinstance(previous_statements, Node):
                graph.add_edge(previous_statements.id, node.id, edge_type="common")

            if node.type == "if_statement":
                if_exit_stat = []
                
                consequence = node.child_by_field_name("consequence")
                end_stat = traverse_build_cfg(consequence, graph, node)
                if isinstance(end_stat, list):
                    if_exit_stat.extend(end_stat)
                elif isinstance(end_stat, Node):
                    if_exit_stat.append(end_stat)
                    
                alternative = node.child_by_field_name("alternative")
                if alternative:
                    graph.add_node(alternative.id, ast_node=alternative, text=alternative.text.decode())
                    graph.add_edge(node.id, alternative.id)
                    end_stat = traverse_build_cfg(alternative, graph, alternative)
                    if isinstance(end_stat, list):
                        if_exit_stat.extend(end_stat)
                    elif isinstance(end_stat, Node):
                        if_exit_stat.append(end_stat)
                else:
                    if_exit_stat.append(node)
                previous_statements = if_exit_stat

            elif node.type == "while_statement":
                body = node.child_by_field_name("body")
                previous_statements = traverse_build_cfg(body, graph, node)
                if isinstance(previous_statements, list):
                    for elem in previous_statements:
                        if elem:
                            graph.add_edge(elem.id, node.id, edge_type="common")
                elif isinstance(previous_statements, Node):
                    graph.add_edge(previous_statements.id, node.id, edge_type="common")
                previous_statements = node
            elif node.type == "do_statement":
                # Add edge from node to body first since do-while executes body before condition
                body = node.child_by_field_name("body")
                if body:
                    # Process the body first
                    previous_statements = traverse_build_cfg(body, graph, node)
                    
                    # After body execution, check condition and loop back
                    if isinstance(previous_statements, list):
                        for elem in previous_statements:
                            if elem:
                                # After body execution, go back to the do-while condition
                                graph.add_edge(elem.id, node.id, edge_type="common")
                    elif isinstance(previous_statements, Node):
                        graph.add_edge(previous_statements.id, node.id, edge_type="common")
                
                # The do-while node itself becomes the previous statement for next statements
                previous_statements = node

            elif node.type == "for_statement":
                body = node.child_by_field_name("body")
                previous_statements = traverse_build_cfg(body, graph, node)
                if isinstance(previous_statements, list):
                    for elem in previous_statements:
                        if elem:
                            graph.add_edge(elem.id, node.id, edge_type="common")
                elif isinstance(previous_statements, Node):
                    graph.add_edge(previous_statements.id, node.id, edge_type="common")
                previous_statements = node

            elif node.type == "switch_statement":
                switch_exit_stat = []
                body = node.child_by_field_name("body")
                if body:
                    for case in body.children:
                        # if case.type == "case_statement":
                            end_stat = traverse_build_cfg(case, graph, node)
                            if isinstance(end_stat, list):
                                switch_exit_stat.extend(end_stat)
                            elif isinstance(end_stat, Node):
                                switch_exit_stat.append(end_stat)

                previous_statements = switch_exit_stat or node
            elif node.type == "case_statement":
                case_prev = node
                for child in node.children:
                    if "statement" in child.type:
                        case_prev = traverse_build_cfg(child, graph, case_prev)
                previous_statements = case_prev
            elif node.type == "return_statement":
                # graph.add_edge(node.id, exit_node)
                # previous_statements = None
                previous_statements = node
            else:
                previous_statements = node

        elif node.type == "function_definition":
            graph.add_node(node.id, ast_node=node, text=node.text.decode())
            if previous_statements is None:
                pass
            elif isinstance(previous_statements, list):
                for elem in previous_statements:
                    if elem:
                        graph.add_edge(elem.id, node.id, edge_type="common")
            elif isinstance(previous_statements, Node):
                graph.add_edge(previous_statements.id, node.id, edge_type="common")

            body = node.child_by_field_name("body")
            previous_statements = traverse_build_cfg(body, graph, node)
        else:
            for child in node.children:
                previous_statements = traverse_build_cfg(child, graph, previous_statements)
        return previous_statements

    previous_statements = traverse_build_cfg(root_node, graph, root_node)
    if isinstance(previous_statements, list):
        for pn in previous_statements:
            if pn:
                graph.add_edge(pn.id, exit_node, edge_type="common")
    elif isinstance(previous_statements, Node):
        graph.add_edge(previous_statements.id, exit_node, edge_type="common")
    return graph, root_node.id, exit_node


def extract_function_definition_lines_c(node: Node):
    lines_row_list = []
    if node.type == "function_definition":
        start_row = node.start_point.row
        end_row = node.child_by_field_name("declarator").end_point.row
        for i in range(start_row, end_row + 1):
            lines_row_list.append(i)
        
        body_node = node.child_by_field_name("body")
        if body_node and body_node.type == "compound_statement":
            for cchild in body_node.children:
                if cchild.type == "{" or cchild.type == '}': 
                    lines_row_list.append(cchild.start_point.row)
        return lines_row_list
        
    for child in node.children:
        lines_row_list.extend(extract_function_definition_lines_c(child))
    return lines_row_list


def project_lineid_into_node_c(pdg: nx.DiGraph, line_id: int) -> List[str]:
    """Given a line id, find which node containing this line. The node can be multiple sometimes."""
    result_node = []
    for node in pdg:
        ast_node = pdg.nodes[node]["ast_node"]
        if ast_node:
            # Get start and end positions from tree-sitter node
            start_row, end_row = identify_row_range_c(ast_node)            
            # Check if line_id falls within this node's range
            if start_row <= line_id <= end_row:
                result_node.append(node)
    return result_node


def from_subgraph_to_lineids_c(subgraph: nx.DiGraph, language):
    """transform the sliced subgraph into corresponding lines for C"""
    all_line_ids = []
    for n in subgraph:
        ast_node = subgraph.nodes[n]["ast_node"]
        start_row, end_row = identify_row_range_c(ast_node)
        for child in ast_node.children:
            if child.type == "compound_statement":
                for cchild in child.children:
                    if cchild.type == "{" or cchild.type == '}': 
                        all_line_ids.append(cchild.start_point.row)
        for l in range(start_row, end_row + 1):
            all_line_ids.append(l)
    all_line_ids = sorted(set(all_line_ids))
    return all_line_ids


def post_add_function_definition_c(code: str, parser: Parser):
    tree = parser.parse(code.encode())
    
    def traverse_if_func_def(node: Node):
        if node.type == "function_definition":
            return True
        for child in node.children:
            if traverse_if_func_def(child):
                return True
        return False
    
    if traverse_if_func_def(tree.root_node):
        return code
    else:
        return "int main(){\n{code}\n}".replace("{code}", code)

def main_c(vulnerable_code: str, secure_code: str):
    """Main entry point for C code analysis"""
    # Initialize the AST and CFG
    parser = Parser(Language(tsc.language()))
    vuln_tree = parser.parse(vulnerable_code.encode("utf-8"))
    sec_tree = parser.parse(secure_code.encode("utf-8"))
    vuln_pdg = build_program_dependence_graph(vuln_tree, "c")
    sec_pdg = build_program_dependence_graph(sec_tree, "c")

    # Identify slicing criteria
    before_modified_lines, after_modified_lines, bl_al_mapping = mapping_two_version_diffs(vulnerable_code, secure_code)
    vuln_slicing_criteria = {x for bml_id in before_modified_lines 
        for x in project_lineid_into_node_c(vuln_pdg, bml_id)}
    sec_slicing_criteria = {x for aml_id in after_modified_lines
        for x in project_lineid_into_node_c(sec_pdg, aml_id)}

    # Perform program slicing
    vuln_subgraph = perform_slicing(vuln_pdg, vuln_slicing_criteria, 2, "both")
    sec_subgraph = perform_slicing(sec_pdg, sec_slicing_criteria, 2, "both")

    # Convert to line numbers
    vuln_lines = from_subgraph_to_lineids_c(vuln_subgraph, "c")
    sec_lines = from_subgraph_to_lineids_c(sec_subgraph, "c")    

    # Merge and generate final output
    vuln_lines, sec_lines = merge_two_version_lines(vuln_lines, sec_lines, bl_al_mapping)
    vuln_sliced_code = lines_to_code(vuln_lines, vulnerable_code)
    sec_sliced_code = lines_to_code(sec_lines, secure_code)

    return vuln_sliced_code, sec_sliced_code
if __name__ == "__main__":
    pass