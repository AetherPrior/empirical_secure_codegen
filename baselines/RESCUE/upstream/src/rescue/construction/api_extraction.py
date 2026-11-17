"""
This module implements API extraction from code.
"""

from pathlib import Path
import json
from tree_sitter import Language, Node, Parser
import tree_sitter_python as tspython
import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
import numpy as np


def init_parser(programming_language):
    """Based on the programming language, build corresponding parsers."""
    if programming_language == "python":
        PYTHON_LANGUAGE = Language(tspython.language())
        parser = Parser(PYTHON_LANGUAGE)
    elif programming_language == "c":
        C_LANGUAGE = Language(tsc.language())
        parser = Parser(C_LANGUAGE)
    return parser


def extract_python_method_calls(code, python_parser):
    code = bytes(code, encoding="utf-8")

    # first parse the code from text into ast
    tree = python_parser.parse(code)
    call_name_list = []

    def traverse(node: Node):
        # if node.type == "assignment":
        #     left_node = node.child_by_field_name("left")
        #     right_node = node.child_by_field_name("right")

        if node.type == "call":
            func_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if func_node.type == "attribute":
                # a.b.c.method()
                object_node = func_node.child_by_field_name("object")
                attribute_node = func_node.child_by_field_name("attribute")
                prefix_name = object_node.text.decode()
                if object_node.type == "identifier":
                    pass
                elif object_node.type == "attribute":
                    pass
                elif object_node.type == "call":
                    pass
                elif object_node.type == "string":
                    prefix_name = "str"
                elif object_node.type == "subscript":
                    pass
                elif object_node.type == "parenthesized_expression":
                    prefix_name = "unknown"
                elif object_node.type == "list":
                    prefix_name = "list"
                elif object_node.type == "dictionary":
                    prefix_name = "dict"
                elif object_node.type == "concatenated_string":
                    prefix_name = "str"
                else:
                    print(object_node.type)
                call_name = attribute_node.text.decode()
                call_name = prefix_name + "." + call_name
                call_name_list.append(call_name)

            elif func_node.type == "identifier":
                call_name = func_node.text.decode()
                call_name_list.append(call_name)
            else:
                #
                # print(func_node.type, node.text.decode())
                pass

            # if args_node:
            #     args = tuple(arg.text.decode() for arg in args_node.children)
            # else:
            #     args = tuple()
            # call_name = func_node.text.decode()
            # call_dict[call_name] = args

        for child in node.children:
            traverse(child)

    traverse(tree.root_node)
    return call_name_list


def extract_c_method_calls(code, c_parser):
    # Parse the C code
    code = bytes(code, encoding="utf-8")

    tree = c_parser.parse(code)
    call_list = []

    # Define the traverse pattern
    def traverse(node):
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if func_node:
                call_list.append(func_node.text.decode())
                # print(func_node.text.decode())
            if args_node:
                # print(args_node.text.decode())
                pass
        
        for child in node.children:
            traverse(child)

    traverse(tree.root_node)
    return call_list


def extract_method_calls(programming_language, code):
    if programming_language in ["python", "py"]:
        parser = init_parser("python")
        return extract_python_method_calls(code, parser)
    elif programming_language in ["c", "cpp"]:
        parser = init_parser("c")
        return extract_c_method_calls(code, parser)
    else:
        return []


if __name__ == '__main__':
    pass