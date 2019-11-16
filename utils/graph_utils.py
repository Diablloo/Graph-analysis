import random
from time import time

from networkx import DiGraph


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
