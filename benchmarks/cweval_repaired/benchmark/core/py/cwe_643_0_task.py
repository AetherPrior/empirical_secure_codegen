
from typing import Dict

from lxml import etree


def get_student_info(
    xml_data: str, username: str, password: str
) -> Dict[str, str] | None:
    """
    Parse xml_data and return information for the first student whose username and password exactly match the supplied strings.

    The XML root is <students> and contains <student> elements with <username>, <password>, <name>, <citizenship>, and <age> children.

    On a match, return a dict containing exactly the keys 'name', 'age', and 'citizenship', with the corresponding text values. Return None if no student matches. Matching is case-sensitive.

    Args:
        xml_data: XML document as a string.
        username: Username to find.
        password: Password to match.

    Returns:
        A three-field student-information dict, or None.
    """
    # BEGIN SOLUTION
    root = etree.fromstring(xml_data)
    query = f"//student[username=$username and password=$password]"
    student = root.xpath(query, username=username, password=password)
    if len(student) == 0:
        return None
    student = student[0]
    return {
        "name": student.find("name").text,
        "age": student.find("age").text,
        "citizenship": student.find("citizenship").text,
    }
