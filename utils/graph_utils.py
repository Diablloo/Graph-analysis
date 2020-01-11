import random
from time import time

from networkx import DiGraph, strongly_connected_components, MultiDiGraph

from utils.threat_calc import ThreatCalculator


def generate_graph(max_nodes: int, max_vulns_per_node: int, max_compromized_from_one_node: int, chance: float = 50):
    """
    Generates random attack graph
    :param chance: from 0 to 100
    :param max_compromized_from_one_node:
    :param max_vulns_per_node:
    :param max_nodes: nodes amount
    :return:
    """
    # random.seed(time())
    random.seed(10)
    edges_count = 0
    nodes_count = 1
    cur_nodes_amount = 1
    step_nodes_count = 1
    graph = MultiDiGraph()
    nodes_list = [0]
    devices = [0]
    vulns = []
    map_node_vulns = {}
    node_vulns = {}

    graph.add_node(nodes_list[0],weight=0)
    while cur_nodes_amount < max_nodes:
        tmp_nodes_list = []
        for node in nodes_list:
            nodes = []
            if cur_nodes_amount == 1:
                step_nodes_amount = random.randint(1, max_compromized_from_one_node)
            else:
                step_nodes_amount = random.randint(0, max_compromized_from_one_node)

            for i in range(step_nodes_amount):
                next_node = cur_nodes_amount
                cur_nodes_amount += 1
                node_vulns[next_node] = []
                nodes.append(next_node)
                graph.add_node(next_node,weight=random.randint(1,10)*10)
                tmp_nodes_list.append(next_node)
                nodes_count += 1

                devices.append(next_node)
                step_vulns_for_node = random.randint(1, max_vulns_per_node)

                for j in range(step_vulns_for_node):
                    threat_level = random.randint(1, 10)
                    cur_vuln = f"CVE_{str(next_node)}_{j}"
                    node_vulns[next_node].append(cur_vuln)
                    vulns.append(cur_vuln)

                    #graph.add_edge(node, cur_vuln, weight=0)
                    graph.add_edge(node, next_node, key=cur_vuln, cve=cur_vuln)
                    edges_count += 1

            for node_first in nodes:
                for node_second in nodes:
                    if node_first == node_second:
                        continue
                    for vuln in node_vulns[node_second]:
                        if random.randint(0, 100) < chance:
                            graph.add_edge(node_first, node_second, key=vuln, cve=vuln)
                            edges_count += 1
            # for key, value in node_vulns.items():
            #     for key_2, value_2 in node_vulns.items():
            #         if key_2 == key:
            #             continue
            #         for vuln_name in value_2:
            #             if random.randint(0, 100) < chance:
            #                 graph.add_edge(key, key_2, cve=vuln_name)
        nodes_list = tmp_nodes_list
        if len(nodes_list) == 0:
            break
        # cur_nodes_amount += len(tmp_nodes_list)
        step_nodes_count = len(tmp_nodes_list)

    return (graph, devices, node_vulns)

def remove_edges_with_cve(graph: MultiDiGraph, cve, target):
    tmp = []
    for u,v in graph.in_edges(target):
        tmp.append([u,v])

    for edge in tmp:
        graph.remove_edge(edge[0],edge[1],cve)

def get_strongly_connected_components(graph: DiGraph, min_nodes_in_component: int = 2):
    """

    :param min_nodes_in_component:
    :param graph:
    :return:
    """
    strong_components = list(strongly_connected_components(graph))
    complex_components = []
    for component in strong_components:
        if len(component) >= min_nodes_in_component:
            complex_components.append(list(component))

    return complex_components

def subgraph_criticality(graph: MultiDiGraph, nodes: set, start_node):
    """

    :param start_node:
    :param graph:
    :param nodes:
    :return:
    """
    assert len(nodes) != 0
    sub_graph = graph.subgraph(nodes)
    calc = ThreatCalculator(sub_graph)

    return calc.calculate_threat_for_node(start_node)

def subgraph_threat(graph: MultiDiGraph, nodes: set, strong: bool = False):
    """
    Определение уровня угрозы для набора точек
    :param strong:
    :param graph:
    :param nodes:
    :return:
    """
    assert len(nodes) != 0
    sub_graph = graph.subgraph(nodes)
    calc = ThreatCalculator(sub_graph)
    if strong:
        return len(nodes) * calc.calculate_threat_for_node(list(nodes)[0])
    else:
        return calc.calculate_graph_threat(list(nodes))


def get_component_out_edges(graph: MultiDiGraph, nodes: list) -> list:
    """
    Return all out edges
    :param graph:
    :param nodes:
    :return: list of out edges
    """
    out_elems = []
    for elem in nodes:
        for u, v, key in graph.out_edges(elem, keys=True):
            if v not in nodes and (u, v, key) not in out_elems:
                out_elems.append([u, v, key])
    return out_elems

def get_component_in_edges(graph: MultiDiGraph, nodes: list) -> list:
    """
    Return all out edges
    :param graph:
    :param nodes:
    :return: list of out edges
    """
    in_elems = []
    for elem in nodes:
        for u, v, key in graph.in_edges(elem, keys=True):
            if u not in nodes and (u, v, key) not in in_elems:
                in_elems.append([u, v, key])
    return in_elems

def map_component_edges(graph: MultiDiGraph, component):
    """
    We look for all outgoing edges to ANOTHER components or nodes
    :param graph:
    :param component:
    :return:
    """
    return get_component_in_edges(graph, component), get_component_out_edges(graph, component)

def map_component_inside_edges(graph: MultiDiGraph, component):
    """
    We look for all outgoing edges to ANOTHER components or nodes
    :param graph:
    :param component:
    :return:
    """
    inside_edges = []
    for node in component:
        for edge in graph.edges(node, keys=True):
            inside_edges.append(edge)
    return inside_edges

def get_sources_to_target_node(graph: MultiDiGraph, target) -> list:
    in_elems = []
    for u, v in graph.in_edges(target):
        if v == target:
            in_elems
