import random
from time import time

from networkx import DiGraph, strongly_connected_components

from utils.threat_calc import ThreatCalculator


def generate_graph(n: int, max_vulns_per_node: int, max_nodes_per_node: int, chance: float = 50):
    """
    Generates random attack graph
    :param chance: from 0 to 100
    :param max_nodes_per_node:
    :param max_vulns_per_node:
    :param n: nodes amount
    :return:
    """
    random.seed(time())
    cur_nodes_amount = 1
    step_nodes_count = 1
    graph = DiGraph()
    nodes_list = [0]
    devices = []
    vulns = []

    while cur_nodes_amount < n:
        tmp_nodes_list = []
        for node in nodes_list:
            node_vulns = {}
            if cur_nodes_amount == 1:
                step_nodes_amount = random.randint(1, max_nodes_per_node)
            else:
                step_nodes_amount = random.randint(0, max_nodes_per_node)

            for i in range(step_nodes_amount):
                next_node = cur_nodes_amount
                cur_nodes_amount += 1
                node_vulns[next_node] = []
                tmp_nodes_list.append(next_node)

                devices.append(next_node)
                step_vulns_for_node = random.randint(1, max_vulns_per_node)

                for j in range(step_vulns_for_node):
                    threat_level = random.randint(1, 10)
                    cur_vuln = f"{str(node)}_{j}_{str(next_node)}"
                    node_vulns[next_node].append(cur_vuln)
                    vulns.append(cur_vuln)

                    graph.add_edge(node, cur_vuln, weight=0)
                    graph.add_edge(cur_vuln, next_node, weight=threat_level)

            for key, value in node_vulns.items():
                for key_2, value_2 in node_vulns.items():
                    if key_2 == key:
                        continue
                    for vuln_name in value_2:
                        if random.randint(0, 100) < chance:
                            graph.add_edge(key, vuln_name, weight=0)
        nodes_list = tmp_nodes_list
        if len(nodes_list) == 0:
            break
        # cur_nodes_amount += len(tmp_nodes_list)
        step_nodes_count = len(tmp_nodes_list)

    return (graph, devices, vulns)


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
            complex_components.append(component)

    return complex_components


def subgraph_threat(graph: DiGraph, nodes: list):
    sub_graph = graph.subgraph(nodes)
    calc = ThreatCalculator(sub_graph)
    assert len(nodes) != 0
    sub_graph_threat = calc.calculate_threat_for_node(nodes.pop())

    return sub_graph_threat


def map_components_to_out_edges(graph: DiGraph, components):
    """
    We look for all outgoing edges to ANOTHER components or nodes
    :param graph:
    :param components:
    :return:
    """
    components_map = []
    for component in components:
        out_elems = []
        for elem in component:
            for u, v in graph.out_edges(elem):
                if v not in component and v not in out_elems:
                    out_elems.append(v)
        components_map.append(out_elems)

    return components_map
