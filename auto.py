import yaml
import os
import re

directory = 'sigma-rules/windows/process_creation'
output_dir = 'ossec-rules/windows/process_creation'


class SigmaOssec(object):
    rulenumber = 0
    data = {}
    common_fields = ['utctime', 'processguid', 'processid', 'image', 'currentdirectory', 'user', 'logonguid',
                     'logonid', 'terminalsessionid', 'integritylevel', 'parentprocessguid', 'parentprocessid',
                     'parentimage', 'parentcommandline', 'originalfilename', 'company', 'username']

    def __init__(self, documentData, rulenumber):
        # static rule entries #
        self.static_ifgroup = ''
        self.static_title = ''
        self.static_title_whitelist = ''
        self.static_lastpart = {}
        self.output = {}
        self.rulenumber = rulenumber
        if len(documentData) != 1:
            self.output['validation_failed_xml'] = 'Manual check needed! More than 1 XML document'
        self.data = documentData[0]
        self.output = self.validate_syntax(self.data, self.output)

    def getOutput(self):
        data = self.data
        # static rule entries #
        self.static_ifgroup = '\t<if_group>sysmon_event1</if_group>'
        self.static_title = self.getTitle(data)
        self.static_title_whitelist = self.getTitle(data, True)
        self.static_lastpart = self.getLastPart(data)
        output = self.output
        if 'detection' not in data.keys():
            output['validation_failed_detection'] = 'Manual check needed! No detection key'
            output['opentag'] = self.getOpenTag(data)
            output['if_group'] = '\t<if_group>sysmon_event1</if_group>'
            output['title'] = self.getTitle(data)
            output = self.getLastPart(data, output)
            return output

        elif self.data['detection']['condition'] in ['selection', '1 of them', 'selection1 or selection2',
                                                'selection1 or selection2 or selection3']:
            output = self.handle_standard_or(data, output)
            return output
        elif self.data['detection']['condition'] in ['selection and not filter']:
            output = self.handle_and_not_filter(data, output)
            output['validation_failed_detection'] = 'Manual check needed! Selection and not filter'
            return output
        else:
            output['validation_failed_detection'] = 'Manual check needed! Unknown condition'
            # manual check needed, for now it will be processed as OR statement
            output = self.handle_standard_or(data, output)
            return output

    def handle_standard_or(self, data, output):
        section_number = 1
        for selection in data['detection']:
            # for each selection a new rule (OR condition)
            if selection != 'condition':
                # start rule
                output['opentag{}'.format(section_number)] = self.getOpenTag(data)
                output['if_group'] = self.static_ifgroup
                # get the detection rules (fieldnames)
                all_rules = []
                for fieldname in data['detection'][selection]:
                    field_rule = self.start_parse(data['detection'][selection], fieldname)
                    for rule in field_rule:
                        all_rules.append(rule)
                output['field_rule{}'.format(section_number)] = all_rules
                # finish with the last part of the rule
                output['title{}'.format(section_number)] = self.static_title
                lastpart = self.static_lastpart
                # merge lastpart in output
                for part in lastpart:
                    output['{}{}'.format(part, section_number)] = lastpart[part]
                output['empty_line{}'.format(section_number)] = ''
            section_number += 1
            self.rulenumber += 1
        return output

    def handle_and_not_filter(self, data, output):
        section_number = 1
        for selection in data['detection']:
            # for each selection a new rule (OR condition)
            if selection != 'condition':
                if selection != 'filter':
                    # start rule
                    output['opentag{}'.format(section_number)] = self.getOpenTag(data)
                    output['if_group'] = self.static_ifgroup
                else:
                    # start rule
                    output['opentag{}'.format(section_number)] = self.getOpenTag(data, True)
                    output['if_group{}'.format(section_number)] = '\t<if_sid>{}</if_sid>'.format(self.rulenumber - 1)
                # get the detection rules (fieldnames)
                all_rules = []
                for fieldname in data['detection'][selection]:
                    field_rule = self.start_parse(data['detection'][selection], fieldname)
                    for rule in field_rule:
                        all_rules.append(rule)
                output['field_rule{}'.format(section_number)] = all_rules
                # Whitelist rules only get the <description> tag
                if selection == 'filter':
                    output['title{}'.format(section_number)] = self.static_title_whitelist
                    output['close_rule{}'.format(section_number)] = '</rule>'
                else:
                    # finish with the last part of the rule
                    output['title{}'.format(section_number)] = self.static_title
                    lastpart = self.static_lastpart
                    # merge lastpart in output
                    for part in lastpart:
                        output['{}{}'.format(part, section_number)] = lastpart[part]
                output['empty_line{}'.format(section_number)] = ''

                section_number += 1
                self.rulenumber += 1
        return output

# ------------- Parse Functions ------------- #
    def start_parse(self, selection, fieldname):
        all_rules = []
        if type(fieldname) == dict:
            # for sub_fieldname in selection[0]:
            #     dict_rules = (self.parse_value_modifiers(selection[0], sub_fieldname))
            #     for rule in dict_rules:
            #         all_rules.append(rule)
            for sub_selection in selection:
                for sub_fieldname in sub_selection:
                    dict_rules = (self.parse_value_modifiers(sub_selection, sub_fieldname))
                    for rule in dict_rules:
                        all_rules.append(rule)
        else:
            all_rules = self.parse_value_modifiers(selection, fieldname)
        return all_rules

    def parse_value_modifiers(self, selection, fieldname):
        field_rules = []
        fieldname_splitted = fieldname.split('|')
        # normal contains
        if len(fieldname_splitted) == 1:
            field_rules.append(self.parse_fieldtype(selection, fieldname))
        elif len(fieldname_splitted) == 2:
            if fieldname_splitted[1].lower() == 'contains':
                # normal contains
                field_rules.append(self.parse_fieldtype(selection, fieldname))
            elif fieldname_splitted[1].lower() == 'startswith':
                # modifier type 1
                field_rules.append(self.parse_fieldtype(selection, fieldname,2))
            elif fieldname_splitted[1].lower() == 'endswith':
                # modifier type 2
                field_rules.append(self.parse_fieldtype(selection, fieldname,2))
        elif len(fieldname_splitted) == 3 and fieldname_splitted[1] == 'contains' and fieldname_splitted[2] == 'all':
            if type(selection[fieldname]) == list:
                for item in selection[fieldname]:
                    field_rules.append(self.parse_fieldtype(item, fieldname))
            elif type(selection[fieldname]) == str:
                field_rules.append(self.parse_fieldtype(selection[fieldname], fieldname))
        else:
            field_rules.append('Manual check needed! Modifier parse failed:{}'.format(fieldname))
            field_rules.append(self.parse_fieldtype(selection, fieldname))
        return field_rules

    def parse_fieldtype(self, selection, fieldname, modifier=0):
        # check if type = dict, if not Sigma rule syntax is wrong
        # Change type to right dict
        if type(selection) is str:
            selection = {fieldname: selection}
        start_string = ''
        end_string = ''
        if modifier == 1:
            start_string = '^'
        elif modifier == 2:
            end_string = '$'
        # try:
        fieldname_stripped = fieldname.split('|')[0].lower()
        if fieldname_stripped in ['commandline', 'command']:
            rule = self.parse_commandline(selection, fieldname, start_string, end_string)
        elif fieldname_stripped in ['sha1', 'sha256', 'md5', 'imphash']:
            rule = self.parse_hash(selection, fieldname)
        elif fieldname_stripped in self.common_fields:
            rule = self.parse_common(selection, fieldname, start_string, end_string)
        else:
            rule = 'Manual check needed! Rule failed Field: {}'.format(fieldname)
        return rule

    def parse_commandline(self, selection, fieldname, start_string, end_string):
        query = ''
        # handle wrong syntax of Sigma > should be dict not str
        if type(selection[fieldname]) == list:
            first_key = True
            for item in selection[fieldname]:
                if not first_key:
                    query += '|'
                else:
                    first_key = False
                # replace with single backslash
                item = self.replace_backslash_wildcard(item, '\\\\')
                item = self.replace_variables(item)
                query += start_string + item + end_string
            return '\t<field name="win.eventdata.CommandLine">{}</field>'.format(query)
        elif type(selection[fieldname]) == str:
            item = selection[fieldname]
            # replace with single backslash
            item = self.replace_backslash_wildcard(item, '\\\\')
            item = self.replace_variables(item)
            query += start_string + item + end_string
            return '\t<field name="win.eventdata.CommandLine">{}</field>'.format(query)
        else:
            return 'Manual check needed! Rule parse failed (Parse Commandline)'

    def parse_hash(self, selection, fieldname):
        fieldname_stripped = fieldname.split('|')[0].lower()
        hash = ''
        if fieldname_stripped == 'sha1':
            hash = 'SHA1='
        elif fieldname_stripped == 'sha256':
            hash = 'SHA256='
        elif fieldname_stripped == 'md5':
            hash = 'MD5='
        elif fieldname_stripped == 'imphash':
            hash = 'IMPHASH='
        query = ''
        if type(selection[fieldname]) == list:
            first_key = True
            for item in selection[fieldname]:
                if not first_key:
                    query += '|'
                else:
                    first_key = False
                query += hash + item
            return '\t<field name="win.eventdata.Hashes">{}</field>'.format(query)
        elif type(selection[fieldname]) == str:
            item = hash + selection[fieldname]
            return '\t<field name="win.eventdata.Hashes">{}</field>'.format(query)
        else:
            return 'Manual check needed! Rule parse failed (Parse Hash)'

    def parse_common(self, selection, fieldname, start_string, end_string):
        fieldname_stripped = fieldname.split('|')[0]
        # replace username with user
        fieldname_stripped = re.sub(r'username', 'User', fieldname_stripped, flags=re.I)
        #fieldname_stripped = fieldname_stripped.replace('Username', 'User').replace('username', 'User').replace('USERNAME', 'User')
        query = ''
        if type(selection[fieldname]) == list:
            first_key = True
            for item in selection[fieldname]:
                if not first_key:
                    query += '|'
                else:
                    first_key = False
                item = self.replace_backslash_wildcard(item)
                item = self.replace_variables(item)
                query += start_string + item + end_string
            return '\t<field name="win.eventdata.{}">{}</field>'.format(fieldname_stripped, query)
        elif type(selection[fieldname]) == str:
            item = selection[fieldname]
            item = self.replace_backslash_wildcard(item)
            item = self.replace_variables(item)
            query += start_string + item + end_string
            return '\t<field name="win.eventdata.{}">{}</field>'.format(fieldname_stripped, query)
        else:
            return 'Manual check needed! Rule parse failed (Parse Common)'

    def replace_variables(self, item):
        # replace ( with \(  (must be escaped)
        item = item.replace('(', '\\(').replace(')', '\\))')
        # replace $ with \$  (must be escaped)
        item = item.replace('$', '\\$')
        # replace | with \|  (must be escaped)
        item = item.replace('|', '\\|')
        # replace < with \<  (must be escaped)
        item = item.replace('<', '\\<')
        # replace ( with \(  (must be escaped)
        item = item.replace('(', '\\(').replace(')', '\\)')
        # replace C driveletter with \.
        item = item.replace('c:\\', '\\.:\\').replace('C:\\', '\\.:\\')
        # replace %APPDATA% with \.\AppData\\.
        item = item.replace('%AppData%', '\\.\\AppData\\\\.').replace('%APPDATA%', '\\.\\AppData\\\\.')
        # replace %System% with \.\AppData\\.
        item = item.replace('%AppData%', '\\.\\AppData\\\\.').replace('%APPDATA%', '\\.\\AppData\\\\.')
        # replace %WINDIR% with \.\Windows\\.
        item = item.replace('%WinDir%', '\\.\\Windows\\\\.').replace('%WINDIR%', '\\.\\Windows\\\\.')
        return item

    def replace_backslash_wildcard(self, item, backshlash='\\\\\\\\'):
        # Write \\\\ if you want two backslahes
        # Write \* if you want a plain wildcard * as resulting value.
        # Write \\* if you want a plain backslash followed by a wildcard * as resulting value.
        # Write \\\* if you want a plain backslash followed by a plain * as resulting value.
        item = item.replace('\\\\\\\\', '%|TWO-P-BACKSLASH|%')
        item = item.replace('\\\\\\*', '%|P-BACKSLASH-P-WILDCARD|%')
        item = item.replace('\\\\*', '%|P-BACKSLASH-WILDCARD')
        item = item.replace('\\*', '%|P-WILDCARD|%')
        item = item.replace('*', '%|WILDCARD|%')
        # double backslash
        item = item.replace('%|TWO-P-BACKSLASH|%', '\\\\')
        item = item.replace('\\', backshlash)
        item = item.replace('%|P-BACKSLASH-P-WILDCARD|%', backshlash + '*')
        item = item.replace('%|P-BACKSLASH-WILDCARD', backshlash + '\\.')
        item = item.replace('%|P-WILDCARD|%', '*')
        item = item.replace('%|WILDCARD|%', '\\.')





        # # standard double backslash > Wazuh events convert \ to \\ (except commandline field)
        # # replace \* and *  with (PLACEHOLDER) to prevent \. is converted to \\.
        # item = item.replace('\\*', '!@#$%^&()PLACEHOLDER')
        # item = item.replace('*', '!@#$%^&()PLACEHOLDER')
        # # replace \ with \\
        # item = item.replace('\\', backshlash)
        # # replace PLACEHOLDER with \.
        # item = item.replace('!@#$%^&()PLACEHOLDER', '\\.')
        return item

    def validate_syntax(self, data, output):
        required = ['title', 'id', 'description', 'level', 'logsource']
        for field in required:
            if field not in data.keys():
                output['validation_failed_{}'.format(field)] = 'Manual check needed! Contains not all required fields: {}'.format(field)
                return output
        return output

    def getOpenTag(self, data, whitelist=False):
        if whitelist:
            return '<rule id="{}" level="{}">'.format(self.rulenumber, 0)
        else:
            level = '%'
            if 'level' in data.keys():
                level = self.convertLevel(data['level'])
            return '<rule id="{}" level="{}">'.format(self.rulenumber, level)

    def getTitle(self, data, whitelist=False):
        start_title = ''
        if whitelist:
            start_tile = 'Whitelist Interaction'
        else:
            start_tile = 'ATT&CK'
            if 'tags' in data.keys():
                for tag in data['tags']:
                    t = re.search('attack\.(t\d*)', tag)
                    if t:
                        start_tile += ' {}'.format(t.group(1).upper())
                    s = re.search('attack\.(s\d*)', tag)
                    if s:
                        start_tile += ' {}'.format(s.group(1).upper())
        return '\t<description>{}: {}</description>'.format(start_tile, data['title'])

    def getLastPart(self, data, output={}):
        output['description'] = '\t<info type="text">{} </info>'.format(data['description'])
        if 'falsepositives' in data.keys():
            falsepositive = 'Falsepositives:'
            for entry in data['falsepositives']:
                falsepositive += ' {}.'.format(entry)
            output['falsepositives'] = '\t<info type="text">{} </info>'.format(falsepositive)
        output['sigma_uuid'] = '\t<info type="text">Sigma UUID: {} </info>'.format(data['id'])
        output['reference'] = []
        if 'references' in data.keys():
            for reference in data['references']:
                output['reference'].append('\t<info type="link">{} </info>'.format(reference))
        group = ''
        if 'tags' in data.keys():
            for tag in data['tags']:
                group += '{},'.format(tag)
        output['group'] = '\t<group>{}MITRE</group>'.format(group)
        output['close_rule'] = '</rule>'
        return output

    def convertLevel(self, level):
        return {
            'critical': 12,
            'high': 12,
            'medium': 8,
            'low': 5
        }.get(level, '%')


def readFile(dir):
    with open(dir, 'r') as file:
        documents = yaml.load_all(file, Loader=yaml.FullLoader)
        data = []
        for item in documents:
            data.append(item)
        return data


def writeFile(output, filename):
    with open(os.path.join(output_dir, filename.replace('.yml', '.xml')), 'w+') as file:
        for line in output:
            if re.match(r"reference", line) or re.match(r"field_rule", line):
                for item in output[line]:
                    file.write('{}\n'.format(item))
            else:
                file.write('{}\n'.format(output[line]))


def main():
    rule_number = 250000
    for filename in os.listdir(directory):
        if filename.endswith(".yml"):
            documentData = readFile(os.path.join(directory, filename))
            sigmaconvert = SigmaOssec(documentData, rule_number)
            output = sigmaconvert.getOutput()
            writeFile(output, filename)
            rule_number += 10


if __name__ == '__main__':
    main()