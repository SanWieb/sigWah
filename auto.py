import yaml
import os
import re

directory = 'sigma-rules/windows/process_creation'
output_dir = 'ossec-rules/windows/process_creation'


class SigmaOssec(object):
    rulenumber = 0
    data = {}
    events ={}
    events['system'] = ['Provider', 'EventID', 'Version', 'Level', 'Task', 'Opcode', 'Keywords', 'TimeCreated', 'EventRecordID', 'Correlation', 'Execution', 'Channel', 'Computer', 'Security']
    events['event1'] = ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'FileVersion', 'CommandLine', 'CurrentDirectory', 'User', 'LogonGuid', 'LogonId', 'TerminalSessionId', 'IntegrityLevel', 'Hashes', 'ParentProcessGuid', 'ParentProcessId', 'ParentImage', 'ParentCommandLine', 'OriginalFilename', 'Description', 'Product', 'Company']
    events['event2'] = ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetFilename', 'CreationUtcTime', 'PreviousCreationUtcTime']
    events['event3'] = ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'User', 'Protocol', 'Initiated', 'SourceIsIpv6', 'SourceIp', 'SourceHostname', 'SourcePort', 'SourcePortName', 'DestinationIsIpv6', 'DestinationIp', 'DestinationHostname', 'DestinationPort', 'DestinationPortName']
    events['event4'] = ['UtcTime', 'State', 'Version', 'SchemaVersion']
    events['event5'] = ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image']
    events['event6'] = ['UtcTime', 'ImageLoaded', 'Hashes', 'Signed', 'Signature', 'SignatureStatus']
    events['event7'] = ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'ImageLoaded', 'Hashes', 'Signed', 'Signature', 'SignatureStatus', 'OriginalFilename']
    events['event8'] = ['UtcTime', 'SourceProcessGuid', 'SourceProcessId', 'SourceImage', 'TargetProcessGuid', 'TargetProcessId', 'TargetImage', 'NewThreadId', 'StartAddress', 'StartModule', 'StartFunction']
    events['event9'] = ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'Device']
    events['event10'] = ['UtcTime', 'SourceProcessGUID', 'SourceProcessId', 'SourceThreadId', 'SourceImage', 'TargetProcessGUID', 'TargetProcessId', 'TargetImage', 'GrantedAccess', 'CallTrace']
    events['event11'] = ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetFilename', 'CreationUtcTime']
    events['event12'] = ['EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetObject']
    events['event13'] = ['EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetObject', 'Details']
    events['event14'] = ['EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetObject', 'NewName']
    events['event15'] = ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetFilename', 'CreationUtcTime', 'Hash']
    events['event16'] = ['UtcTime', 'Configuration', 'ConfigurationFileHash']
    events['event17'] = ['UtcTime', 'ProcessGuid', 'ProcessId', 'PipeName', 'Image']
    events['event18'] = ['UtcTime', 'ProcessGuid', 'ProcessId', 'PipeName', 'Image']
    events['event19'] = ['EventType', 'UtcTime', 'Operation', 'User', 'EventNamespace', 'Name', 'Query']
    events['event20'] = ['EventType', 'UtcTime', 'Operation', 'User', 'Name', 'Type', 'Destination']
    events['event21'] = ['EventType', 'UtcTime', 'Operation', 'User', 'Consumer', 'Filter']
    events['event22'] = ['QueryName', 'QueryStatus', 'QueryResults']
    events['event225'] = []
    events['powershell'] = ['contextinfo', 'message', 'scriptblocktext', 'engineversion', 'hostversion', 'hostname', 'hostapplication']
    events['extra_fields'] = ['servicename', 'taskname', 'qname', 'groupname', 'processname', 'parentintegritylevel', 'parentuser']
    events['syntax_errors'] = ['command', 'username', 'processcommandline', 'newprocessname', 'TargetProcessAddress']
    known_fields = []
    for event in events:
        known_fields += [x.lower() for x in events[event]]
    known_fields = list(set(known_fields))

    commandline_fields = ['commandline', 'command', 'parentcommandline']
    hash_fields = ['sha1', 'sha256', 'md5', 'imphash']
    require_start_end = ['sourceport', 'destinationport']

    def __init__(self, document_data, rulenumber):
        # static rule entries #
        self.static_ifgroup = ''
        self.static_title = ''
        self.static_title_whitelist = ''
        self.static_lastpart = {}
        self.static_lastpart_whitelist = ''
        self.output = {}
        self.rulenumber = rulenumber
        self.document_data = document_data
        self.output = self.validate_syntax(self.data, self.output)

    def get_output(self):
        document_data = self.document_data
        # static rule entries #
        self.static_ifgroup = '\t<if_group>sysmon_event1</if_group>'
        self.static_title = self.get_title(document_data[0])
        self.static_title_whitelist = self.get_title(document_data[0], True)
        self.static_lastpart = self.get_last_part(document_data[0])
        self.static_lastpart_whitelist = self.get_last_part(document_data[0], True)
        output_all = {}
        document_number = 1
        for data in document_data:
            output = {}
            if 'detection' not in data.keys():
                if document_number == 1 and len(document_data) > 1:
                    # not a problem if the first document of a series does not contain any detection
                    continue
                output['validation_failed_detection'] = 'Manual check needed! No detection key'
                output['opentag'] = self.get_open_tag(data)
                output['if_group'] = '\t<if_group>sysmon_event1</if_group>'
                output['title'] = self.static_title
                lastpart = self.static_lastpart
                # merge lastpart in output
                for part in lastpart:
                    output['{}'.format(part)] = lastpart[part]
                output['empty_line'] = ''
            elif 'condition' not in data['detection'].keys() and 'detection' not in document_data[0].keys() and 'condition' not in document_data[0]['detection'].keys():
                    output['validation_failed_detection'] = 'Manual check needed! No condition'
                    # manual check needed, for now it will be processed as OR statement
                    output = self.handle_standard_or(data, output)
            else:
                if 'condition' not in data['detection'].keys():
                    condition = document_data[0]['detection']['condition']
                else:
                    condition = data['detection']['condition']
                if self.is_and_statement(condition):
                    output['validation_failed_detection'] = 'Manual check needed! And condition'
                    output = self.handle_and(data, output)
                elif self.is_or_statement(condition):
                    output = self.handle_standard_or(data, output)
                elif self.is_and_not_statement(condition):
                    output = self.handle_and_not_filter(data, output)
                else:
                    output['validation_failed_detection'] = 'Manual check needed! Unknown condition {}'.format(condition)
                    # manual check needed, for now it will be processed as OR statement
                    output = self.handle_standard_or(data, output)
            # merge the document
            for lines in output:
                output_all['{}{}'.format(lines, document_number)] = output[lines]
            document_number += 1
        return output_all

    # -----------  Handle the several conditions ------------- #

    def handle_standard_or(self, data, output):
        section_number = 1
        for selection in data['detection']:
            # for each selection a new rule (OR condition)
            if selection != 'condition':
                self.get_event_id(data, data['detection'][selection])
                # start rule
                output['opentag{}'.format(section_number)] = self.get_open_tag(data)
                output['if_group{}'.format(section_number)] = self.get_event_id(data, data['detection'][selection])
                # get the detection rules (fieldnames)
                all_rules = self.start_parse(data['detection'][selection])
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
        detection = data['detection']['condition'].split(' ')[0]
        filter = data['detection']['condition'].split(' ')[3]
        for selection in [detection, filter]:
            # for each selection a new rule (OR condition)
            if selection != 'condition':
                if selection != filter:
                    # start rule
                    output['opentag{}'.format(section_number)] = self.get_open_tag(data)
                    output['if_group{}'.format(section_number)] = self.get_event_id(data, data['detection'][selection])
                else:
                    # start rule
                    output['opentag{}'.format(section_number)] = self.get_open_tag(data, True)
                    output['if_group{}'.format(section_number)] = '\t<if_sid>{}</if_sid>'.format(self.rulenumber - 1)
                # get the detection rules (fieldnames)
                all_rules = self.start_parse(data['detection'][selection])
                output['field_rule{}'.format(section_number)] = all_rules
                # Whitelist rules only get the <description> tag
                if selection == filter:
                    output['title{}'.format(section_number)] = self.static_title_whitelist
                    lastpart = self.static_lastpart_whitelist
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

    def handle_and(self, data, output):
        section_number = 1
        output['opentag'] = self.get_open_tag(data)
        # get eventID for all rules (selection)
        output['if_group'] = ''
        # check if there is a selection item with event id
        for selection in data['detection']:
            if type(data['detection'][selection]) is dict:
                selection_lower = {k.lower(): v for k, v in data['detection'][selection].items()}
                if 'eventid' in selection_lower:
                    output['if_group'] = self.get_event_id(data, data['detection'][selection])
                    break
        # else check the header part
        if output['if_group'] == '':
            output['if_group'] = self.get_event_id(data, None)
        for selection in data['detection']:
            # for each selection a new rule (OR condition)
            if selection != 'condition':
                # get the detection rules (fieldnames)
                all_rules = self.start_parse(data['detection'][selection])
                output['field_rule{}'.format(section_number)] = all_rules
            section_number += 1
        # finish with the last part of the rule
        output['title'] = self.static_title
        lastpart = self.static_lastpart
        # merge lastpart in output
        for part in lastpart:
            output['{}'.format(part)] = lastpart[part]
        output['empty_line'] = ''
        return output

    # -----------  Condition Checkers ------------- #
    def is_or_statement(self, condition):
        condition_parts = condition.split(' ')
        if len(condition_parts) == 1 or condition.lower() == '1 of them':
            return True
        elif len(condition_parts) > 2:
            i = 1
            while len(condition_parts) > i:
                if condition_parts[i].lower() != 'or':
                    return False
                # only odd numbers
                i += 2
            return True
    def is_and_statement(self, condition):
        if condition == 'all of them':
            return True
        condition_parts = condition.split(' ')
        if len(condition_parts) > 2:
            i = 1
            while len(condition_parts) > i:
                if condition_parts[i].lower() != 'and':
                    return False
                # only odd numbers
                i += 2
            return True
        else:
            return False
    def is_and_not_statement(self, condition):
        condition_parts = condition.split(' ')
        if len(condition_parts) == 4 and condition_parts[1].lower() == 'and' and condition_parts[2].lower() == 'not':
            return True
        else:
            return False

    # ------------- Parse Functions ------------- #
    def start_parse(self, selection_list):
        # Change all types to list
        # Some Sigma syntax is wrong (dict in a list)
        # Easiest way to solve is to set everything in list
        if type(selection_list) is dict:
            selection_list = [selection_list]
        all_rules = []
        for selection in selection_list:
            for fieldname in selection:
                if not re.match(r'eventid', fieldname, re.IGNORECASE):
                    sub_rules = self.parse_value_modifiers(selection, fieldname)
                    for rule in sub_rules:
                        all_rules.append(rule)
        return all_rules

    def parse_value_modifiers(self, selection, fieldname):
        field_rules = []
        fieldname_splitted = fieldname.split('|')
        # normal contains
        if fieldname_splitted[0].lower() in self.require_start_end:
            field_rules.append(self.parse_fieldtype(selection, fieldname, 3))
        elif len(fieldname_splitted) == 1:
            field_rules.append(self.parse_fieldtype(selection, fieldname))
        elif len(fieldname_splitted) == 2:
            if fieldname_splitted[1].lower() == 'contains':
                # normal contains
                field_rules.append(self.parse_fieldtype(selection, fieldname))
            elif fieldname_splitted[1].lower() == 'startswith':
                # modifier type 1
                print('bingo ' + fieldname)
                field_rules.append(self.parse_fieldtype(selection, fieldname, 1))
            elif fieldname_splitted[1].lower() == 'endswith':
                # modifier type 2
                field_rules.append(self.parse_fieldtype(selection, fieldname,2))
            else:
                field_rules.append('Manual check needed! Modifier parse failed:{}'.format(fieldname))
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
        if type(selection) is str:
            # Change type to  dict
            selection = {fieldname: selection}
        start_string = ''
        end_string = ''
        if modifier == 1:
            start_string = '^'
        elif modifier == 2:
            end_string = '$'
        elif modifier == 3:
            start_string = '^'
            end_string = '$'
        # try:
        fieldname_stripped = fieldname.split('|')[0].lower()
        if fieldname_stripped in self.hash_fields:
            rule = self.parse_hash(selection, fieldname)
        elif fieldname_stripped in self.known_fields:
            rule = self.parse_common(selection, fieldname, start_string, end_string)
        else:
            rule = 'Manual check needed! Rule failed Field: {}'.format(fieldname)
        return rule

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
                if item is None:
                    query += 'null|^$|^ $|^-$'
                else:
                    query += hash + item
            return '\t<field name="win.eventdata.Hashes">{}</field>'.format(query)
        elif type(selection[fieldname]) == str:
            query = hash + selection[fieldname]
            return '\t<field name="win.eventdata.Hashes">{}</field>'.format(query)
        else:
            return 'Manual check needed! Rule parse failed (Parse Hash)'

    def parse_common(self, selection, fieldname, start_string, end_string):
        fieldname_stripped = fieldname.split('|')[0]
        # replace username with user
        fieldname_stripped = re.sub(r'username', 'User', fieldname_stripped, flags=re.I)
        # replace NewProcessName with image
        fieldname_stripped = re.sub(r'newprocessname', 'Image', fieldname_stripped, flags=re.I)
        # replace Command with CommandLine
        fieldname_stripped = re.sub(r'^command$', 'CommandLine', fieldname_stripped, flags=re.I)
        # replace ProcessCommandLine with CommandLine
        fieldname_stripped = re.sub(r'processcommandline', 'CommandLine', fieldname_stripped, flags=re.I)
        # replace TargetProcessAddress with StartAdress
        fieldname_stripped = re.sub(r'targetprocessaddress', 'StartAddress', fieldname_stripped, flags=re.I)
        query = ''
        item_list = selection[fieldname]
        if type(selection[fieldname]) != list:
            item_list = [item_list]
        first_key = True
        for item in item_list:
            if not first_key:
                query += '|'
            else:
                first_key = False
            if type(item) == str:
                item = self.replace_backslash_wildcard(item)
                item = self.replace_variables(item)
                if fieldname_stripped.lower() in self.commandline_fields:
                    item = self.replace_space(item)
            elif item is None:
                item = 'null|^$|^ $|^-$'
            elif type(item) != int:
                return 'Manual check needed! Rule parse failed (Parse Common)'
            query += '{}{}{}'.format(start_string, item, end_string)
        return '\t<field name="win.eventdata.{}">{}</field>'.format(fieldname_stripped, query)

    # -----------  Replace Functions ------------- #

    def replace_backslash_wildcard(self, item, backslash='\\\\\\\\'):
        # Write \\\\ if you want two backslashes
        # Write \* if you want a plain wildcard * as resulting value.
        # Write \\* if you want a plain backslash followed by a wildcard * as resulting value.
        # Write \\\* if you want a plain backslash followed by a plain * as resulting value.
        item = item.replace('\\\\\\\\', '%|TWO-P-BACKSLASH|%')
        item = item.replace('\\\\\\*', '%|P-BACKSLASH-P-WILDCARD|%')
        item = item.replace('\\\\*', '%|P-BACKSLASH-WILDCARD|%')
        item = item.replace('\\*', '%|P-WILDCARD|%')
        item = item.replace('*', '%|WILDCARD|%')
        # double backslash
        item = item.replace('%|TWO-P-BACKSLASH|%', '\\\\')
        item = item.replace('\\', backslash)
        item = item.replace('%|P-BACKSLASH-P-WILDCARD|%', backslash + '\\.*')
        item = item.replace('%|P-BACKSLASH-WILDCARD|%', backslash + '\\.*')
        item = item.replace('%|P-WILDCARD|%', '\\.*')
        item = item.replace('%|WILDCARD|%', '\\.*')
        # remove wildcard start and end of string
        item = re.sub(r'\\\.\*$', '', item)
        item = re.sub(r'^\\\.\*', '', item)
        return item

    def replace_variables(self, item):
        # ! backslashes
        # replace ( with \(  (must be escaped)
        item = item.replace('(', '\\(').replace(')', '\\)')
        # replace $ with \$  (must be escaped)
        item = item.replace('$', '\\$')
        # replace | with \|  (must be escaped)
        item = item.replace('|', '\\|')
        # replace < with \<  (must be escaped)
        item = item.replace('<', '\\<')
        # \p will match asterisk or plus, along with some other characters
        item = item.replace('+', '\\p')
        # replace C driveletter with \.
        item = item.replace('c:\\', '\\.:\\').replace('C:\\', '\\.:\\')
        # replace %APPDATA% with \.AppData\.
        item = re.sub(r'%AppData%', '\\.*AppData\\.*', item, flags=re.I)
        # replace %System% with \.system32\.
        item = re.sub(r'%System%', '\\.*system32\\.*', item, flags=re.I)
        # replace %WINDIR% with \.Windows\.
        item = re.sub(r'%WinDir%', '\\.*Windows\\.*', item, flags=re.I)
        # remove wildcard start and end of string
        item = re.sub(r'\\\.\*$', '', item)
        item = re.sub(r'^\\\.\*', '', item)
        return item

    def replace_space(self, item):
        # Eventlog places sometimes 2 spaces instead of 1 between 2 arguments
        # Replace a space with \s+ parameter
        # If wildcard (\.) is before or after space is it not needed
        item = re.sub(r'\s$', '%|SpaceEnd|%', item)
        item = re.sub(r'^\s', '%|SpaceStart|%', item)
        item = item.replace(' \\.* ', '%|SpaceWildcardSpace|%')
        item = item.replace(' \\.*', '%|SpaceWildcard|%')
        item = item.replace('\\.* ', '%|WildcardSpace|%')
        item = item.replace(' ', '\\s+')
        item = item.replace('%|SpaceEnd|%', ' ')
        item = item.replace('%|SpaceStart|%', ' ')
        item = item.replace('%|SpaceWildcardSpace|%', ' \\.* ')
        item = item.replace('%|SpaceWildcard|%', ' \\.*', )
        item = item.replace('%|WildcardSpace|%', '\\.* ')
        return item

    def validate_syntax(self, data, output):
        required = ['title', 'id', 'description', 'level', 'logsource']
        for field in required:
            if field not in data.keys():
                output['validation_failed_{}'.format(field)] = 'Manual check needed! Contains not all required fields: {}'.format(field)
                return output
        return output

    # -----------  Get Information Functions ------------- #

    def get_open_tag(self, data, whitelist=False):
        if whitelist:
            return '<rule id="{}" level="{}">'.format(self.rulenumber, 0)
        else:
            level = '%'
            if 'level' in data.keys():
                level = self.convert_level(data['level'])
            elif 'level' in self.document_data[0]:
                level = self.convert_level(self.document_data[0]['level'])
            return '<rule id="{}" level="{}">'.format(self.rulenumber, level)

    def get_event_id(self, data, selection):
        if type(selection) is dict:
            selection_lower = {k.lower(): v for k, v in selection.items()}
            if 'eventid' in selection_lower:
                event_id = selection_lower['eventid']
                if type(event_id) is list:
                    first_key = True
                    query = ''
                    for item in event_id:
                        if not first_key:
                            query += '|'
                        else:
                            first_key = False
                        query += '^{}$'.format(item)
                    return '\t<field name="win.system.EventID">{}</field>'.format(query)
                else:
                    if event_id < 16:
                        if event_id > 9:
                            return '\t<if_group>sysmon_event_{}</if_group>'.format(event_id)
                        else:
                            return '\t<if_group>sysmon_event{}</if_group>'.format(event_id)
                    else:
                        return '\t<field name="win.system.EventID">^{}$</field>'.format(event_id)
        if 'logsource' in data and 'category' in data['logsource'] and 'product' in data['logsource']:
            if data['logsource']['category'] == 'process_creation' and data['logsource']['product'] == 'windows':
                return '\t<if_group>sysmon_event1</if_group>'
        elif 'logsource' in data and 'service' in data['logsource'] and 'product' in data['logsource']:
            if data['logsource']['service'] == 'process_creation' and data['logsource']['product'] == 'windows':
                return '\t<if_group>sysmon_event1</if_group>'
        else:
            first_document = self.document_data[0]
            if 'logsource' in first_document and 'category' in first_document['logsource'] and 'product' in first_document['logsource']:
                if first_document['logsource']['category'] == 'process_creation' and first_document['logsource']['product'] == 'windows':
                    return '\t<if_group>sysmon_event1</if_group>'
        return 'Manual check needed! Doublecheck no EventID'

    def get_title(self, data, whitelist=False):
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

    def get_last_part(self, data, whitelist=False):
        output = {}
        if not whitelist:
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

    def convert_level(self, level):
        return {
            'critical': 15,
            'high': 14,
            'medium': 10,
            'low': 8
        }.get(level, '%')

# -----------  Read / Write Functions ------------- #


def read_file(dir):
    with open(dir, 'r') as file:
        documents = yaml.load_all(file, Loader=yaml.FullLoader)
        data = []
        for item in documents:
            data.append(item)
        return data


def write_file(output, filename):
    with open(os.path.join(output_dir, filename.replace('.yml', '.xml')), 'w+') as file:
        for line in output:
            if re.match(r"reference", line) or re.match(r"field_rule", line):
                for item in output[line]:
                    file.write('{}\n'.format(item))
            else:
                file.write('{}\n'.format(output[line]))


# -----------  Main ------------- #

def main():
    rule_number = 260000
    for filename in os.listdir(directory):
        if filename.endswith(".yml"):
            print(filename)
            document_data = read_file(os.path.join(directory, filename))
            sigmaconvert = SigmaOssec(document_data, rule_number)
            output = sigmaconvert.get_output()
            write_file(output, filename)
            rule_number += 10


if __name__ == '__main__':
    main()