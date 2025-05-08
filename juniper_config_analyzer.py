#!/usr/bin/env python3
from lxml import etree
import networkx as nx
import jxmlease
import argparse
import sys
import logging

# Настройка логирования с уровнем DEBUG
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class ConfigNode:
    """Класс для представления узла в иерархической модели конфигурации."""
    def __init__(self, name, parent=None):
        self.name = name
        self.parent = parent
        self.children = {}
        self.attributes = {}

    def add_child(self, child_node):
        """Добавляет дочерний узел."""
        self.children[child_node.name] = child_node

    def add_attribute(self, key, value):
        """Добавляет атрибут узла."""
        self.attributes[key] = value

    def get_path(self):
        """Возвращает путь от корня до текущего узла."""
        path = []
        node = self
        while node.parent:
            path.insert(0, node.name)
            node = node.parent
        return ' > '.join(path)

def build_config_tree(xml_root, parent=None):
    """Рекурсивно строит дерево ConfigNode из XML-структуры."""
    if isinstance(xml_root, jxmlease.XMLDictNode):
        for key, value in xml_root.items():
            if isinstance(value, jxmlease.XMLDictNode):
                node = ConfigNode(key, parent)
                parent.add_child(node)
                build_config_tree(value, node)
            elif isinstance(value, list):
                for item in value:
                    node = ConfigNode(key, parent)
                    parent.add_child(node)
                    build_config_tree(item, node)
            else:
                parent.add_attribute(key, value)
    elif isinstance(xml_root, jxmlease.XMLListNode):
        for item in xml_root:
            build_config_tree(item, parent)

def find_unused_elements(root):
    """Находит неиспользуемые элементы конфигурации."""
    ns = {'junos': 'http://xml.juniper.net/junos/18.2R3/junos'}
    types = {
        'prefix-list': {
            'defined': '//*[local-name()="prefix-list"]/*[local-name()="name"]/text()',
            'referenced': '//*[local-name()="prefix-list-name"]/text()'
        },
        'community': {
            'defined': '//*[local-name()="community"]/*[local-name()="name"]/text()',
            'referenced': '//*[local-name()="community-name"]/text()'
        },
        'as-path': {
            'defined': '//*[local-name()="as-path"]/*[local-name()="name"]/text()',
            'referenced': '//*[local-name()="from"]/*[local-name()="as-path"]/text()'
        },
        'policy-statement': {
            'defined': '//*[local-name()="policy-statement"]/*[local-name()="name"]/text()',
            'referenced': '//*[local-name()="policy-name"]/text()'
        },
        'bgp-group': {
            'defined': '//*[local-name()="bgp"]/*[local-name()="group"]/*[local-name()="name"]/text()',
            'referenced': '//*[local-name()="peer-group"]/text()'
        }
    }

    unused_elements = {}
    # Отладка: поиск всех policy-statement
    policy_statements = root.xpath('//*[local-name()="policy-statement"]', namespaces=ns)
    logging.debug(f"Найдено policy-statement: {len(policy_statements)} элементов")
    for ps in policy_statements:
        try:
            name_elements = ps.xpath('*[local-name()="name"]', namespaces=ns)
            name = name_elements[0].text if name_elements else None
            if name:
                path = '/'.join(ps.getroottree().getpath(ps).split('/')[1:])
                ns_prefix = ps.prefix if ps.prefix else 'none'
                logging.debug(f"Найден policy-statement: {name} в пути: {path}, пространство имен: {ns_prefix}")
        except Exception as e:
            logging.debug(f"Ошибка при обработке policy-statement: {str(e)}")

    # Отладка: поиск всех bgp group
    bgp_groups = root.xpath('//*[local-name()="bgp"]/*[local-name()="group"]', namespaces=ns)
    logging.debug(f"Найдено bgp-group: {len(bgp_groups)} элементов")
    for group in bgp_groups:
        try:
            name_elements = group.xpath('*[local-name()="name"]', namespaces=ns)
            name = name_elements[0].text if name_elements else None
            if name:
                path = '/'.join(group.getroottree().getpath(group).split('/')[1:])
                ns_prefix = group.prefix if group.prefix else 'none'
                logging.debug(f"Найден bgp-group: {name} в пути: {path}, пространство имен: {ns_prefix}")
        except Exception as e:
            logging.debug(f"Ошибка при обработке bgp-group: {str(e)}")

    for type_name, paths in types.items():
        defined = set(root.xpath(paths['defined'], namespaces=ns) or [])
        referenced = set(root.xpath(paths['referenced'], namespaces=ns) or [])
        logging.debug(f"{type_name} - Определения: {defined}")
        logging.debug(f"{type_name} - Ссылки: {referenced}")
        unused = defined - referenced
        if unused:
            unused_elements[type_name] = list(unused)
    return unused_elements

def build_dependency_graph(root):
    """Строит граф зависимостей."""
    G = nx.DiGraph()
    ns = {'junos': 'http://xml.juniper.net/junos/18.2R3/junos'}
    # Проверка наличия ключевых элементов
    groups = root.xpath('//*[local-name()="groups"]', namespaces=ns)
    policy_options = root.xpath('//*[local-name()="policy-options"]', namespaces=ns)
    routing_options = root.xpath('//*[local-name()="routing-options"]', namespaces=ns)
    protocols = root.xpath('//*[local-name()="protocols"]', namespaces=ns)
    bgp = root.xpath('//*[local-name()="protocols"]/*[local-name()="bgp"]', namespaces=ns)
    apply_groups = root.xpath('//*[local-name()="apply-groups"]', namespaces=ns)
    logging.debug(f"Найдено groups: {len(groups)} элементов")
    logging.debug(f"Найдено policy-options: {len(policy_options)} элементов")
    logging.debug(f"Найдено routing-options: {len(routing_options)} элементов")
    logging.debug(f"Найдено protocols: {len(protocols)} элементов")
    logging.debug(f"Найдено bgp: {len(bgp)} элементов")
    logging.debug(f"Найдено apply-groups: {len(apply_groups)} элементов")

    # Добавление узлов и ребер для политик и их зависимостей
    for policy in root.xpath('//*[local-name()="policy-statement"]', namespaces=ns):
        try:
            name_elements = policy.xpath('*[local-name()="name"]', namespaces=ns)
            policy_name = name_elements[0].text if name_elements else None
            if policy_name:
                logging.debug(f"Обработка policy-statement: {policy_name}")
                for term in policy.xpath('*[local-name()="term"]', namespaces=ns):
                    for from_sect in term.xpath('*[local-name()="from"]', namespaces=ns):
                        for pl_name in from_sect.xpath('*[local-name()="prefix-list-name"]/text()', namespaces=ns):
                            G.add_edge(f"policy-statement.{policy_name}", f"prefix-list.{pl_name}")
                            logging.debug(f"Добавлено ребро: policy-statement.{policy_name} -> prefix-list.{pl_name}")
                        for comm_name in from_sect.xpath('*[local-name()="community-name"]/text()', namespaces=ns):
                            G.add_edge(f"policy-statement.{policy_name}", f"community.{comm_name}")
                            logging.debug(f"Добавлено ребро: policy-statement.{policy_name} -> community.{comm_name}")
                        for as_path in from_sect.xpath('*[local-name()="as-path"]/text()', namespaces=ns):
                            G.add_edge(f"policy-statement.{policy_name}", f"as-path.{as_path}")
                            logging.debug(f"Добавлено ребро: policy-statement.{policy_name} -> as-path.{as_path}")
        except Exception as e:
            logging.debug(f"Ошибка при обработке policy-statement: {str(e)}")

    # Добавление узлов и ребер для BGP-групп
    for group in root.xpath('//*[local-name()="protocols"]/*[local-name()="bgp"]/*[local-name()="group"]', namespaces=ns):
        try:
            name_elements = group.xpath('*[local-name()="name"]', namespaces=ns)
            group_name = name_elements[0].text if name_elements else None
            if group_name:
                logging.debug(f"Обработка bgp-group: {group_name}")
                for policy_name in group.xpath('*[local-name()="import"]/*[local-name()="policy-name"]/text()', namespaces=ns) + group.xpath('*[local-name()="export"]/*[local-name()="policy-name"]/text()', namespaces=ns):
                    G.add_edge(f"bgp-group.{group_name}", f"policy-statement.{policy_name}")
                    logging.debug(f"Добавлено ребро: bgp-group.{group_name} -> policy-statement.{policy_name}")
        except Exception as e:
            logging.debug(f"Ошибка при обработке bgp-group: {str(e)}")

    logging.debug(f"Граф содержит {G.number_of_nodes()} узлов и {G.number_of_edges()} ребер")
    return G

def find_independent_components(G):
    """Находит независимые компоненты графа."""
    components = list(nx.weakly_connected_components(G))
    independent = []
    for component in components:
        if not any(G.in_degree(node) > 0 for node in component for pred in G.predecessors(node) if pred not in component):
            independent.append(component)
    logging.debug(f"Найдено {len(components)} компонент, из них {len(independent)} независимых")
    return independent

def main():
    # Обработка аргументов командной строки
    parser = argparse.ArgumentParser(description="Анализ конфигурации Juniper из XML-файла")
    parser.add_argument('xml_file', type=str, help="Путь к XML-файлу конфигурации")
    args = parser.parse_args()

    # Загрузка XML
    logging.info(f"Загрузка файла {args.xml_file}")
    try:
        with open(args.xml_file, 'r') as f:
            xml_str = f.read()
        xml_root = etree.fromstring(xml_str)
    except FileNotFoundError:
        logging.error(f"Файл {args.xml_file} не найден")
        sys.exit(1)
    except etree.XMLSyntaxError:
        logging.error(f"Файл {args.xml_file} содержит некорректный XML")
        sys.exit(1)

    # Вывод первых 1000 символов XML для отладки
    logging.debug("Фрагмент XML (первые 1000 символов):")
    logging.debug(xml_str[:1000])

    # Проверка пространства имен
    namespaces = xml_root.nsmap
    logging.debug(f"Пространства имен в XML: {namespaces}")

    # Парсинг XML с помощью jxmlease для построения дерева
    try:
        config_dict = jxmlease.parse(xml_str)
        root_node = ConfigNode('configuration')
        if 'rpc-reply' in config_dict and 'configuration' in config_dict['rpc-reply']:
            build_config_tree(config_dict['rpc-reply']['configuration'], root_node)
        else:
            logging.error("XML не содержит элемента <rpc-reply><configuration>")
            sys.exit(1)
    except Exception as e:
        logging.error(f"Ошибка при парсинге XML: {str(e)}")
        sys.exit(1)

    # Проверка наличия ключевых элементов
    ns = {'junos': 'http://xml.juniper.net/junos/18.2R3/junos'}
    for section in ['groups', 'policy-options', 'routing-options', 'protocols', 'bgp', 'apply-groups']:
        count = len(xml_root.xpath(f'//*[local-name()="{section}"]', namespaces=ns))
        logging.debug(f"Найдено {section}: {count} элементов")

    # Поиск неиспользуемых элементов
    logging.info("Поиск неиспользуемых элементов")
    unused_elements = find_unused_elements(xml_root)
    if unused_elements:
        print("Неиспользуемые элементы:")
        for type_name, elements in unused_elements.items():
            print(f"  {type_name}: {', '.join(elements)}")
    else:
        print("Неиспользуемые элементы не найдены")

    # Построение и анализ графа зависимостей
    logging.info("Построение графа зависимостей")
    G = build_dependency_graph(xml_root)
    independent_components = find_independent_components(G)
    if independent_components:
        print("\nНезависимые компоненты графа зависимостей:")
        for i, component in enumerate(independent_components, 1):
            print(f"  Компонента {i}: {', '.join(component)}")
    else:
        print("\nНезависимые компоненты не найдены")

if __name__ == "__main__":
    main()
