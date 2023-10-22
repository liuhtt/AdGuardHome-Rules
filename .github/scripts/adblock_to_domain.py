import re


class AdblockRuleDecoder:
    def remove_http_https_prefix(self, value):
        # 检查开头是否为"http://"或"https://"
        if value.startswith("http://"):
            # 去除前缀
            value = value[len("http://"):]
        elif value.startswith("https://"):
            # 去除前缀
            value = value[len("https://"):]
        return value

    def remove_port_from_value(self, value):
        # 检查末尾是否为端口
        port_pattern = re.compile(r":\d+$")
        if re.search(port_pattern, value):
            # 去除端口
            value = re.sub(port_pattern, "", value)
        return value

    def check_value_type(self, value):
        # 检查是否为IP地址
        ip_pattern = re.compile(
            r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        )
        if re.match(ip_pattern, value):
            return 'IP'

        # 检查是否为KEYWORD
        keyword_pattern = re.compile(
            r"^[a-zA-Z0-9_\-]+$"
        )
        if re.match(keyword_pattern, value):
            return 'KEYWORD'

        # 检查是否为域名
        domain_pattern = re.compile(
            r"^(?:[a-zA-Z0-9_\-]+\.)+[a-zA-Z]{2,}$"
        )
        if re.match(domain_pattern, value):
            return 'DOMAIN'

        # 检查是否为正则表达式
        try:
            re.compile(value)
            return 'REGEX'
        except re.error:
            pass

        return 'UNKNOWN'

    def decode_adblock_rule(self, adblock_rules):

        original_rules = adblock_rules.split('\n')
        rules = []
        if len(original_rules) == 0:
            return rules
        for rule in original_rules:
            action = ''
            unsupport = False
            rule_type = ''

            if len(rule) <= 1:
                continue
            if rule[-1] == '\r':
                rule = rule[0:-1]
            if '#' in rule:
                unsupport = True
            if rule[0] == '[' and rule[-1] == ']':  # 去除 [AutoProxy 0.2.9]
                continue
            elif rule[0] == '!':  # 去除注释行
                continue
            elif rule[0] == '|':
                exclude_rule = False
                if rule[1] == '|':
                    rule_type = 'domain/keyword'
                    start_str = 2
                else:
                    rule_type = 'URL'
                    start_str = 1
            elif rule[0:2] == '@@':
                exclude_rule = True
                if rule[2] == '|':
                    if rule[3] == '|':
                        rule_type = 'domain/keyword'
                        start_str = 4
                    else:
                        rule_type = 'URL'
                        start_str = 3
                else:
                    unsupport = True
            elif rule[1] == '/':
                rule_type = 'REGEX'
                unsupport = True
            else:
                rule_type = 'pure domain/ip/regex'
                start_str = 0
            if unsupport:
                if exclude_rule:
                    action = 'EXCLUDE'
                else:
                    action = 'UNKNOWN'
                if not rule_type:
                    rule_type = 'UNKNOWN'
                rules.append({'rule': rule, 'domain': 'UNSUPPORT', 'ip': 'UNSUPPORT', 'type': rule_type, 'style': 'UNKNOWN', 'result': action})
                continue

            rule2 = rule[start_str:]
            if rule2[-1] == '^':
                rule2 = rule2[0:-1]
            if rule_type == 'domain/keyword':
                if rule2[:2] == '*.':
                    rule2 = rule2[2:]
                rule2 == self.remove_port_from_value(rule2)
                rule_type_check_result = self.check_value_type(rule2)
                if rule_type_check_result in ['DOMAIN', 'KEYWORD']:
                    unsupport = False
                else:
                    unsupport = True
            elif rule_type == 'URL':
                rule2 = self.remove_http_https_prefix(rule2)
                if rule2[:2] == '*.':
                    rule2 = rule2[2:]
                if rule2[-1] == '/':
                    rule2 = rule2[0:-1]
                rule2 == self.remove_port_from_value(rule2)
                rule_type_check_result = self.check_value_type(rule2)
                if rule_type_check_result == 'DOMAIN':
                    unsupport = False
                else:
                    unsupport = True
            elif rule_type == 'pure domain/ip/regex':
                rule_type_check_result = self.check_value_type(rule2)
                exclude_rule = True
                if rule_type_check_result in ['DOMAIN', 'KEYWORD', 'IP']:
                    unsupport = False
                else:
                    unsupport = True
            else:
                rule_type_check_result = self.check_value_type(rule2)
                rule_type = 'UNKNOWN'
                action = 'UNKNOWN'
                unsupport = True
            rule_style = rule_type_check_result
            if unsupport:
                if action != 'UNKNOWN':
                    if exclude_rule:
                        action = 'EXCLUDE'
                    else:
                        action = 'ICLUDED'
                rules.append({'rule': rule, 'domain': 'UNSUPPORT', 'ip': 'UNSUPPORT', 'type': rule_type, 'style': rule_style, 'result': action})
                continue
            else:
                if exclude_rule:
                    action = 'EXCLUDE'
                else:
                    action = 'ICLUDED'
                if rule_style == 'IP':
                    rules.append({'rule': rule, 'domain': '', 'ip': rule2, 'type': rule_type, 'style': rule_style, 'result': action})
                elif rule_style == 'DOMAIN':
                    rules.append({'rule': rule, 'domain': rule2, 'ip': '', 'type': rule_type, 'style': rule_style, 'result': action})
        return rules


def adblock_to_domain(adblock_rules):
    China_domain_list = []
    Overseas_domain_list = []
    decoder = AdblockRuleDecoder()

    rules = decoder.decode_adblock_rule(adblock_rules)
    for rule in rules:
        if rule['domain'] and not rule['domain'] == 'UNSUPPORT':
            if rule['result'] == 'EXCLUDE':
                China_domain_list.append(rule['domain'])
            elif rule['result'] == 'ICLUDED':
                Overseas_domain_list.append(rule['domain'])

    return China_domain_list, Overseas_domain_list
