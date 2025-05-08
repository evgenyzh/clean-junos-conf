#!/usr/bin/env python3
from lxml import etree
import networkx as nx
import jxmlease
import argparse
import sys
import logging
import re

# Настройка логирования с уровнем DEBUG
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Кастомный фильтр для отладочных логов по имени сущности
class EntityFilter(logging.Filter):
    def __init__(self, entity_name=None):
        super().__init__()
        self.entity_name = entity_name

    def filter(self, record):
        if self.entity_name:
            return self.entity_name in record.getMessage()
        return True

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

def collect_policy_dependencies(root, policy_name, used_elements, ns, visited=None):
    """Рекурсивно собирает зависимости политики."""
    if visited is None:
        visited = set()
    if policy_name in visited:
        logging.debug(f"Политика {policy_name} уже обработана, пропускаем")
        return
    visited.add(policy_name)
    logging.debug(f"Сбор зависимостей для policy-statement: {policy_name}")
    used_elements['policy-statement'].add(policy_name)
    
    # Поиск зависимостей политики
    policy_xpath = f'//*[local-name()="policy-statement" and *[local-name()="name" and text()="{policy_name}"]]'
    # Обработка prefix-list через <prefix-list-name>
    for pl_name in root.xpath(f'{policy_xpath}//*[local-name()="prefix-list-name"]/text()', namespaces=ns):
        used_elements['prefix-list'].add(pl_name)
        logging.debug(f"Добавлен prefix-list (prefix-list-name): {pl_name}")
    # Обработка prefix-list через <from><prefix-list><name>
    for pl_name in root.xpath(f'{policy_xpath}//*[local-name()="from"]/*[local-name()="prefix-list"]/*[local-name()="name"]/text()', namespaces=ns):
        used_elements['prefix-list'].add(pl_name)
        logging.debug(f"Добавлен prefix-list (prefix-list): {pl_name}")
    # Обработка коммьюнити в <from><community> и <then><community><community-name>
    for comm_name in root.xpath(f'{policy_xpath}//*[local-name()="from"]/*[local-name()="community"]/text() | {policy_xpath}//*[local-name()="then"]/*[local-name()="community"]/*[local-name()="community-name"]/text()', namespaces=ns):
        if comm_name.strip():  # Исключаем пустые строки
            used_elements['community'].add(comm_name)
            logging.debug(f"Добавлен community: {comm_name}")
        else:
            logging.debug(f"Пропущен пустой community в политике {policy_name}")
    # Обработка as-path, указанных непосредственно
    for as_path in root.xpath(f'{policy_xpath}//*[local-name()="as-path"]/text()', namespaces=ns):
        used_elements['as-path'].add(as_path)
        logging.debug(f"Добавлен as-path: {as_path}")
    # Обработка as-path-group
    for as_path_group in root.xpath(f'{policy_xpath}//*[local-name()="as-path-group"]/text()', namespaces=ns):
        if as_path_group.strip():  # Исключаем пустые строки
            used_elements['as-path-group'].add(as_path_group)
            logging.debug(f"Добавлен as-path-group: {as_path_group}")
            # Находим все as-path внутри as-path-group
            as_path_group_xpath = f'//*[local-name()="as-path-group" and *[local-name()="name" and text()="{as_path_group}"]]'
            for as_path_name in root.xpath(f'{as_path_group_xpath}/*[local-name()="as-path"]/*[local-name()="name"]/text()', namespaces=ns):
                used_elements['as-path'].add(as_path_name)
                logging.debug(f"Добавлен as-path: {as_path_name} из as-path-group: {as_path_group}")
    # Рекурсивный поиск других политик через apply-policy, policy-name или from/policy
    for sub_policy in root.xpath(f'{policy_xpath}//*[local-name()="apply-policy"]/text() | {policy_xpath}//*[local-name()="policy-name"]/text() | {policy_xpath}//*[local-name()="from"]/*[local-name()="policy"]/text()', namespaces=ns):
        logging.debug(f"Найдена подполитика: {sub_policy} для {policy_name}")
        collect_policy_dependencies(root, sub_policy, used_elements, ns, visited)

def find_unused_elements(root, used_elements):
    """Находит неиспользуемые элементы конфигурации, исключая использованные."""
    ns = {'junos': 'http://xml.juniper.net/junos/18.2R3/junos'}
    types = {
        'prefix-list': {
            'defined': '//*[local-name()="prefix-list"]/*[local-name()="name"]/text()',
            'referenced': '//*[local-name()="prefix-list-name"]/text() | //*[local-name()="from"]/*[local-name()="prefix-list"]/*[local-name()="name"]/text()'
        },
        'community': {
            'defined': '//*[local-name()="policy-options"]//*[local-name()="community"]/*[local-name()="name"]/text()',
            'referenced': '//*[local-name()="community"]/text() | //*[local-name()="community-name"]/text()'
        },
        'as-path': {
            'defined': '//*[local-name()="as-path"]/*[local-name()="name"]/text()',
            'referenced': '//*[local-name()="from"]/*[local-name()="as-path"]/text() | //*[local-name()="as-path-group"]/*[local-name()="as-path"]/*[local-name()="name"]/text()'
        },
        'as-path-group': {
            'defined': '//*[local-name()="as-path-group"]/*[local-name()="name"]/text()',
            'referenced': '//*[local-name()="from"]/*[local-name()="as-path-group"]/text()'
        },
        'policy-statement': {
            'defined': '//*[local-name()="policy-statement"]/*[local-name()="name"]/text()',
            'referenced': '//*[local-name()="policy-name"]/text() | //*[local-name()="apply-policy"]/text() | //*[local-name()="from"]/*[local-name()="policy"]/text()'
        },
        'bgp-group': {
            'defined': '//*[local-name()="bgp"]/*[local-name()="group"]/*[local-name()="name"]/text()',
            'referenced': '//*[local-name()="peer-group"]/text()'
        }
    }

    unused_elements = {}
    # Отладка: поиск всех policy-statement с указанием их расположения
    policy_statements = root.xpath('//*[local-name()="policy-statement"]', namespaces=ns)
    logging.debug(f"Найдено policy-statement: {len(policy_statements)} элементов")
    for ps in policy_statements:
        try:
            name_elements = ps.xpath('*[local-name()="name"]', namespaces=ns)
            name = name_elements[0].text if name_elements else None
            if name:
                path = '/'.join(ps.getroottree().getpath(ps).split('/')[1:])
                ns_prefix = ps.prefix if ps.prefix else 'none'
                in_groups = 'groups' in path.lower()
                location = 'в groups' if in_groups else 'глобально'
                logging.debug(f"Найден policy-statement: {name} в пути: {path}, пространство имен: {ns_prefix}, расположение: {location}")
        except Exception as e:
            logging.debug(f"Ошибка при обработке policy-statement: {str(e)}")

    # Отладка: поиск всех as-path-group
    as_path_groups = root.xpath('//*[local-name()="as-path-group"]', namespaces=ns)
    logging.debug(f"Найдено as-path-group: {len(as_path_groups)} элементов")
    for apg in as_path_groups:
        try:
            name_elements = apg.xpath('*[local-name()="name"]', namespaces=ns)
            name = name_elements[0].text if name_elements else None
            if name:
                path = '/'.join(apg.getroottree().getpath(apg).split('/')[1:])
                ns_prefix = apg.prefix if apg.prefix else 'none'
                in_groups = 'groups' in path.lower()
                location = 'в groups' if in_groups else 'глобально'
                logging.debug(f"Найден as-path-group: {name} в пути: {path}, пространство имен: {ns_prefix}, расположение: {location}")
        except Exception as e:
            logging.debug(f"Ошибка при обработке as-path-group: {str(e)}")

    for type_name, paths in types.items():
        defined = set(root.xpath(paths['defined'], namespaces=ns) or [])
        logging.debug(f"{type_name} - Все определения: {defined}")
        logging.debug(f"{type_name} - Используемые: {used_elements.get(type_name, set())}")
        # Исключаем использованные элементы
        unused = defined - used_elements.get(type_name, set())
        logging.debug(f"{type_name} - Неиспользуемые: {unused}")
        if unused:
            unused_elements[type_name] = list(unused)
    return unused_elements

def build_dependency_graph(root):
    """Строит граф зависимостей и определяет использованные элементы."""
    G = nx.DiGraph()
    ns = {'junos': 'http://xml.juniper.net/junos/18.2R3/junos'}
    used_elements = {
        'prefix-list': set(),
        'community': set(),
        'as-path': set(),
        'as-path-group': set(),
        'policy-statement': set(),
        'bgp-group': set()
    }

    # Проверка наличия ключевых элементов
    groups = root.xpath('//*[local-name()="groups"]', namespaces=ns)
    policy_options = root.xpath('//*[local-name()="policy-options"]', namespaces=ns)
    routing_options = root.xpath('//*[local-name()="routing-options"]', namespaces=ns)
    protocols = root.xpath('//*[local-name()="protocols"]', namespaces=ns)
    bgp = root.xpath('//*[local-name()="protocols"]/*[local-name()="bgp"]', namespaces=ns)
    apply_groups = root.xpath('//*[local-name()="apply-groups"]', namespaces=ns)
    as_path_groups = root.xpath('//*[local-name()="as-path-group"]', namespaces=ns)
    logging.debug(f"Найдено groups: {len(groups)} элементов")
    logging.debug(f"Найдено policy-options: {len(policy_options)} элементов")
    logging.debug(f"Найдено routing-options: {len(routing_options)} элементов")
    logging.debug(f"Найдено protocols: {len(protocols)} элементов")
    logging.debug(f"Найдено bgp: {len(bgp)} элементов")
    logging.debug(f"Найдено apply-groups: {len(apply_groups)} элементов")
    logging.debug(f"Найдено as-path-group: {len(as_path_groups)} элементов")

    # Добавление узлов и ребер для политик и их зависимостей
    for policy in root.xpath('//*[local-name()="policy-statement"]', namespaces=ns):
        try:
            name_elements = policy.xpath('*[local-name()="name"]', namespaces=ns)
            policy_name = name_elements[0].text if name_elements else None
            if policy_name:
                logging.debug(f"Обработка policy-statement: {policy_name}")
                for term in policy.xpath('*[local-name()="term"]', namespaces=ns):
                    for from_sect in term.xpath('*[local-name()="from"]', namespaces=ns):
                        # Обработка prefix-list через <prefix-list-name>
                        for pl_name in from_sect.xpath('*[local-name()="prefix-list-name"]/text()', namespaces=ns):
                            G.add_edge(f"policy-statement.{policy_name}", f"prefix-list.{pl_name}")
                            logging.debug(f"Добавлено ребро: policy-statement.{policy_name} -> prefix-list.{pl_name}")
                        # Обработка prefix-list через <prefix-list><name>
                        for pl_name in from_sect.xpath('*[local-name()="prefix-list"]/*[local-name()="name"]/text()', namespaces=ns):
                            G.add_edge(f"policy-statement.{policy_name}", f"prefix-list.{pl_name}")
                            logging.debug(f"Добавлено ребро: policy-statement.{policy_name} -> prefix-list.{pl_name}")
                        for comm_name in from_sect.xpath('*[local-name()="community"]/text()', namespaces=ns):
                            if comm_name.strip():  # Исключаем пустые строки
                                G.add_edge(f"policy-statement.{policy_name}", f"community.{comm_name}")
                                logging.debug(f"Добавлено ребро: policy-statement.{policy_name} -> community.{comm_name}")
                            else:
                                logging.debug(f"Пропущен пустой community в политике {policy_name}")
                        for as_path in from_sect.xpath('*[local-name()="as-path"]/text()', namespaces=ns):
                            G.add_edge(f"policy-statement.{policy_name}", f"as-path.{as_path}")
                            logging.debug(f"Добавлено ребро: policy-statement.{policy_name} -> as-path.{as_path}")
                        for as_path_group in from_sect.xpath('*[local-name()="as-path-group"]/text()', namespaces=ns):
                            if as_path_group.strip():  # Исключаем пустые строки
                                G.add_edge(f"policy-statement.{policy_name}", f"as-path-group.{as_path_group}")
                                logging.debug(f"Добавлено ребро: policy-statement.{policy_name} -> as-path-group.{as_path_group}")
                                # Находим все as-path внутри as-path-group
                                as_path_group_xpath = f'//*[local-name()="as-path-group" and *[local-name()="name" and text()="{as_path_group}"]]'
                                for as_path_name in root.xpath(f'{as_path_group_xpath}/*[local-name()="as-path"]/*[local-name()="name"]/text()', namespaces=ns):
                                    G.add_edge(f"as-path-group.{as_path_group}", f"as-path.{as_path_name}")
                                    logging.debug(f"Добавлено ребро: as-path-group.{as_path_group} -> as-path.{as_path_name}")
                        for sub_policy in from_sect.xpath('*[local-name()="policy"]/text()', namespaces=ns):
                            G.add_edge(f"policy-statement.{policy_name}", f"policy-statement.{sub_policy}")
                            logging.debug(f"Добавлено ребро: policy-statement.{policy_name} -> policy-statement.{sub_policy}")
                    # Обработка коммьюнити в <then><community><community-name>
                    for then_sect in term.xpath('*[local-name()="then"]', namespaces=ns):
                        for comm_name in then_sect.xpath('*[local-name()="community"]/*[local-name()="community-name"]/text()', namespaces=ns):
                            if comm_name.strip():  # Исключаем пустые строки
                                G.add_edge(f"policy-statement.{policy_name}", f"community.{comm_name}")
                                logging.debug(f"Добавлено ребро: policy-statement.{policy_name} -> community.{comm_name}")
                            else:
                                logging.debug(f"Пропущен пустой community в политике {policy_name}")
        except Exception as e:
            logging.debug(f"Ошибка при обработке policy-statement {policy_name}: {str(e)}")

    # Добавление узлов и ребер для BGP-групп и определение активных групп
    active_groups = set()
    for group in root.xpath('//*[local-name()="protocols"]/*[local-name()="bgp"]/*[local-name()="group"]', namespaces=ns):
        try:
            name_elements = group.xpath('*[local-name()="name"]', namespaces=ns)
            group_name = name_elements[0].text if name_elements else None
            if group_name:
                # Проверка активности группы по наличию neighbor с name
                neighbors = group.xpath('*[local-name()="neighbor"]/*[local-name()="name"]/text()', namespaces=ns)
                is_active = len(neighbors) > 0
                path = '/'.join(group.getroottree().getpath(group).split('/')[1:])
                ns_prefix = group.prefix if group.prefix else 'none'
                in_groups = 'groups' in path.lower()
                location = 'в groups' if in_groups else 'глобально'
                logging.debug(f"Найден bgp-group: {group_name} в пути: {path}, пространство имен: {ns_prefix}, расположение: {location}, активна: {is_active}, соседи: {neighbors}")
                if is_active:
                    active_groups.add(group_name)
                    used_elements['bgp-group'].add(group_name)
                    # Собираем политики из import и export
                    for policy_expr in group.xpath('.//*[local-name()="import"]/text() | .//*[local-name()="export"]/text()', namespaces=ns):
                        # Обрабатываем логическое выражение
                        expr = policy_expr.replace('(', '').replace(')', '').strip()
                        policy_names = [p.strip() for p in re.split(r'\|\||&&|;|\s+', expr) if p.strip() and re.match(r'^[\w-]+$', p.strip())]
                        logging.debug(f"Обработано выражение '{policy_expr}' -> политики: {policy_names}")
                        for pn in policy_names:
                            used_elements['policy-statement'].add(pn)
                            G.add_edge(f"bgp-group.{group_name}", f"policy-statement.{pn}")
                            logging.debug(f"Добавлено ребро: bgp-group.{group_name} -> policy-statement.{pn}")
                            collect_policy_dependencies(root, pn, used_elements, ns)
        except Exception as e:
            logging.debug(f"Ошибка при обработке bgp-group: {str(e)}")

    logging.debug(f"Активные BGP-группы: {active_groups}")
    logging.debug(f"Используемые элементы: {used_elements}")
    logging.debug(f"Граф содержит {G.number_of_nodes()} узлов и {G.number_of_edges()} ребер")
    return G, used_elements

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
    parser.add_argument('--filter-entity', '-f', type=str, help="Фильтрация отладочных логов по имени сущности (например, ebgp-import-generic)")
    args = parser.parse_args()

    # Применение фильтра для отладочных логов
    if args.filter_entity:
        entity_filter = EntityFilter(args.filter_entity)
        logger.addFilter(entity_filter)
        logging.info(f"Фильтрация отладочных логов по сущности: {args.filter_entity}")

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
    for section in ['groups', 'policy-options', 'routing-options', 'protocols', 'bgp', 'apply-groups', 'as-path-group']:
        count = len(xml_root.xpath(f'//*[local-name()="{section}"]', namespaces=ns))
        logging.debug(f"Найдено {section}: {count} элементов")

    # Построение графа зависимостей и сбор использованных элементов
    logging.info("Построение графа зависимостей")
    G, used_elements = build_dependency_graph(xml_root)

    # Поиск неиспользуемых элементов
    logging.info("Поиск неиспользуемых элементов")
    unused_elements = find_unused_elements(xml_root, used_elements)
    if unused_elements:
        print("Неиспользуемые элементы:")
        for type_name, elements in unused_elements.items():
            print(f"  {type_name}: {', '.join(elements)}")
    else:
        print("Неиспользуемые элементы не найдены")

    # Анализ независимых компонент
    independent_components = find_independent_components(G)
    if independent_components:
        print("\nНезависимые компоненты графа зависимостей:")
        for i, component in enumerate(independent_components, 1):
            print(f"  Компонента {i}: {', '.join(component)}")
    else:
        print("\nНезависимые компоненты не найдены")

if __name__ == "__main__":
    main()
