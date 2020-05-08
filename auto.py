import yaml
import os
import re

directory = 'sigma-rules/windows/process_creation'
output_dir = 'ossec-rules/windows/process_creation'


class SigmaOssec(object):
    rulenumber = 0
    data = {}

    def __init__(self, documentData, rulenumber):
        self.output = {}
        self.rulenumber = rulenumber
        if len(documentData) != 1:
            self.output['validation_failed_xml'] = 'Manual check needed! More than 1 XML document'
        self.data = documentData[0]
        self.output = self.validateSyntax(self.data, self.output)

    def getOutput(self):
        data = self.data
        output = self.output
        if 'detection' not in data.keys():
            output['validation_failed_detection'] = 'Manual check needed! No detection'
            output['opentag'] = self.getOpenTag(data)
            output['if_group'] = '\t<if_group>sysmon_event_%</if_group>'
            output['title'] = self.getTitle(data)
            output = self.getLastPart(data, output)
            return output

        elif self.data['detection']['condition'] in ['selection', '1 of them', 'selection1 or selection2',
                                                'selection1 or selection2 or selection3']:
            output = self.handleOrRule(data, output)
            return output
        elif self.data['detection']['condition'] in ['selection and not filter']:
            output['validation_failed_detection'] = 'Manual check needed! No detection'
            return output
        else:
            output['validation_failed_detection'] = 'Manual check needed! No detection'
            return output

    def handleOrRule(self, data, output):
        for selection in data['detection']:
            # for each selection a new rule (OR condition)
            section_number = 1
            if selection != 'condition':
                # start rule
                output['opentag{}'.format(section_number)] = self.getOpenTag(data)
                output['if_group'] = '\t<if_group>sysmon_event_%</if_group>'
                # get the detection rules (fieldnames)
                field_rule = []
                for fieldname in data['detection'][selection]:
                    try:
                        fieldname_stripped = fieldname.split('|')[0]
                        if fieldname_stripped.lower() == 'commandline':
                            query = self.parse_commandline(data['detection'][selection], fieldname)
                            print(query)
                            field_rule.append('\t<field name="win.eventdata.CommandLine">{}</field>'.format(query))
                    except Exception as e:
                        field_rule.append('Manual check needed! Rule failed')
                # finish with the last part of the rule
                output['field_rule{}'.format(section_number)] = field_rule
                output['title{}'.format(section_number)] = self.getTitle(data)
                lastpart = self.getLastPart(data)
                # merge lastpart in output
                for part in lastpart:
                    output['{}{}'.format(part, section_number)] = lastpart[part]
                output['empty_line{}'.format(section_number)] = ''
        return output

# ------------- Parse Functions ------------- #

    def parse_commandline(self, selection, fieldname):
        query = ''
        if type(selection[fieldname]) == list:
            first_key = True
            for item in selection[fieldname]:
                if not first_key:
                    query += '|'
                else:
                    first_key = False
                # replace \* with \.
                item = item.replace('\\*', '\\.')
                # replace * with \.
                item = item.replace('*', '\\.')
                item = self.replace_variables(item)
                query += item
            return query
        elif type(selection[fieldname]) == str:
            item = selection[fieldname]
            # replace \* with \.
            item = item.replace('\\*', '\\.')
            # replace * with \.
            item = item.replace('*', '\\.')
            item = self.replace_variables(item)
            query += item
            return query
        else:
            return 'Manual check needed! Rule parse failed'

    def replace_variables(self, item):
        # replace ( with \(  (must be escaped)
        item = item.replace('(', '\\(').replace(')', '\\))')
        # replace C driveletter with \.
        item = item.replace('c:\\', '\\.:\\').replace('C:\\', '\\.:\\')
        # replace %APPDATA% with \.\AppData\\.
        item = item.replace('%AppData%', '\\.\\AppData\\\\.').replace('%APPDATA%', '\\.\\AppData\\\\.')
        # replace %WINDIR% with \.\Windows\\.
        item = item.replace('%WinDir%', '\\.\\Windows\\\\.').replace('%WINDIR%', '\\.\\Windows\\\\.')
        return item


    def validateSyntax(self, data, output):
        required = ['title', 'id', 'description', 'level', 'logsource']
        for field in required:
            if field not in data.keys():
                output['validation_failed_{}'.format(field)] = 'Manual check needed! Contains not all required fields: {}'.format(field)
                return output
        return output

    def getOpenTag(self, data):
        level = '%'
        if 'level' in data.keys():
            level = self.convertLevel(data['level'])
        return '<rule id="{}" level="{}">'.format(self.rulenumber, level)

    def getTitle(self, data):
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