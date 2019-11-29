from time import time

import requests
import json

from networkx import DiGraph

'''
Make link:
https://3vis.neobit.ru/api/graph/link

{"sourceId":7710,"targetId":7690,"pid":"503868d2-97f8-4274-b0f5-46034000803f"}

Make node:
need to get id:
response['msg']['node']['id']
'''
class GraphCreationError(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class GraphVisualizer:
    def __init__(self, graph_name):
        self.name = graph_name
        self.graph_id = None
        self.graph_links = []
        self.nodes_map = {}
        self.auth_token = ("BEARER eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NzcyOTk5ODgsImlhdCI6MTU3NDcwNzk4OCw"
                           "iaWQiOjUsInN1YiI6Im9ybHlfdGVzdGVyIn0.MI8itHOSF81GOKwjMgfXTSCztlceTd6reJHO33VeqP8")
    def create_graph(self):
        r = requests.post('https://3vis.neobit.ru/api/projects', json={"name": self.name},
                          headers={"Authorization":self.auth_token})


        if r.status_code != 200:
            raise GraphCreationError("Graph was not created")

        try:
            response = json.loads(r.text)
        except Exception as ex:
            raise GraphCreationError(f"Graph creation response error: {ex}")

        self.graph_id = response['msg']['project']['id']

    def delete_graph(self):
        r = requests.delete(f'https://3vis.neobit.ru/api/projects/{self.graph_id}', json={"pid": self.graph_id},
                          headers={"Authorization":self.auth_token})


        if r.status_code != 200:
            raise GraphCreationError("Graph was not deleted")

    def add_node(self, node_name, node_type):
        node_params = {
                        "node":
                           {
                               "name":node_name,"type":node_type
                           },
                       "pid": self.graph_id,
                       "needCompare":False
        }
        st = time()
        r = requests.post("https://3vis.neobit.ru/api/graph/node", json=node_params,
                          headers={"Authorization":self.auth_token})
        fin = time() - st
        if r.status_code != 200:
            raise GraphCreationError("Node '{node_name}' type '{node_type}' was not created")

        try:
            response = json.loads(r.text)
        except Exception as ex:
            raise GraphCreationError(f"Graph node creation response error: {ex}")

        self.nodes_map[node_name] = response['msg']['node']['id']

    def add_link(self, first_node_name, second_node_name, cve):
        link_params = {"sourceId": self.nodes_map[first_node_name], "targetId": self.nodes_map[second_node_name],
                       "pid":self.graph_id}
        r = requests.post('https://3vis.neobit.ru/api/graph/link', json=link_params,
                           headers={"Authorization":self.auth_token})
        
        try:
            response = json.loads(r.text)
        except Exception as ex:
            raise GraphCreationError(f"Graph node creation response error: {ex}")

        self.graph_links.append((first_node_name, second_node_name, cve))

    def read_graph(self, graph: DiGraph):
        self.create_graph()
        node_type = 'ip'

        for node in graph.nodes:
            self.add_node(node,node_type)

        for edge in graph.edges:
            self.add_link(edge[0],edge[1],'cve_1')

if __name__ == '__main__':
    vizual = GraphVisualizer("test_graph")
    vizual.create_graph()
    vizual.add_node('test_node', 'ip')
    vizual.add_node('test_node_2', 'ip')
    vizual.add_link('test_node', 'test_node_2', 'cve-1')
    vizual.delete_graph()
