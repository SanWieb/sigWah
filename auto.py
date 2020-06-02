#!/usr/bin/env python3
# A Sigma to Wazuh converter
# Copyright 2020 - 2021 Sander Wiebing

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import yaml
import os
import datetime
import re
import argparse

__version__ = '0.0.1'


class SigWah(object):
    rulenumber = 0
    data = {}
    # hardcoded known events field to minimize syntax and parse errors
    events = {'system': ['Provider', 'EventID', 'Version', 'Level', 'Task', 'Opcode', 'Keywords', 'TimeCreated',
                         'EventRecordID', 'Correlation', 'Execution', 'Channel', 'Computer', 'Security'],
              'event1': ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'FileVersion', 'CommandLine',
                         'CurrentDirectory', 'User', 'LogonGuid', 'LogonId', 'TerminalSessionId', 'IntegrityLevel',
                         'Hashes', 'ParentProcessGuid', 'ParentProcessId', 'ParentImage', 'ParentCommandLine',
                         'OriginalFilename', 'Description', 'Product', 'Company'],
              'event2': ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetFilename', 'CreationUtcTime',
                         'PreviousCreationUtcTime'],
              'event3': ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'User', 'Protocol', 'Initiated',
                         'SourceIsIpv6', 'SourceIp', 'SourceHostname', 'SourcePort', 'SourcePortName',
                         'DestinationIsIpv6', 'DestinationIp', 'DestinationHostname', 'DestinationPort',
                         'DestinationPortName'], 'event4': ['UtcTime', 'State', 'Version', 'SchemaVersion'],
              'event5': ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image'],
              'event6': ['UtcTime', 'ImageLoaded', 'Hashes', 'Signed', 'Signature', 'SignatureStatus'],
              'event7': ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'ImageLoaded', 'Hashes', 'Signed', 'Signature',
                         'SignatureStatus', 'OriginalFilename'],
              'event8': ['UtcTime', 'SourceProcessGuid', 'SourceProcessId', 'SourceImage', 'TargetProcessGuid',
                         'TargetProcessId', 'TargetImage', 'NewThreadId', 'StartAddress', 'StartModule',
                         'StartFunction'], 'event9': ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'Device'],
              'event10': ['UtcTime', 'SourceProcessGUID', 'SourceProcessId', 'SourceThreadId', 'SourceImage',
                          'TargetProcessGUID', 'TargetProcessId', 'TargetImage', 'GrantedAccess', 'CallTrace'],
              'event11': ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetFilename', 'CreationUtcTime'],
              'event12': ['EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetObject'],
              'event13': ['EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetObject', 'Details'],
              'event14': ['EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetObject', 'NewName'],
              'event15': ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetFilename', 'CreationUtcTime', 'Hash'],
              'event16': ['UtcTime', 'Configuration', 'ConfigurationFileHash'],
              'event17': ['UtcTime', 'ProcessGuid', 'ProcessId', 'PipeName', 'Image'],
              'event18': ['UtcTime', 'ProcessGuid', 'ProcessId', 'PipeName', 'Image'],
              'event19': ['EventType', 'UtcTime', 'Operation', 'User', 'EventNamespace', 'Name', 'Query'],
              'event20': ['EventType', 'UtcTime', 'Operation', 'User', 'Name', 'Type', 'Destination'],
              'event21': ['EventType', 'UtcTime', 'Operation', 'User', 'Consumer', 'Filter'],
              'event22': ['QueryName', 'QueryStatus', 'QueryResults'], 'event225': [],
              'powershell': ['contextinfo', 'message', 'scriptblocktext', 'engineversion', 'hostversion', 'hostname',
                             'hostapplication'],
              'windows_security': ['ObjectName', 'accesses', 'accesslist', 'accessmask', 'accountname',
                                   'allowedtodelegateto', 'attributeldapdisplayname', 'attributevalue',
                                   'auditpolicychanges', 'authenticationpackagename', 'callingprocessname',
                                   'computername', 'destinationaddress', 'destport', 'deviceclassname',
                                   'devicedescription', 'failurecode', 'groupsid', 'hivename', 'imagepath', 'ipaddress',
                                   'keylength', 'layerrtid', 'ldapdisplayname', 'logonprocessname', 'logontype',
                                   'objectclass', 'objectserver', 'objecttype', 'objectvaluename', 'passwordlastset',
                                   'path', 'privilegelist', 'properties', 'relativetargetname', 'samaccountname',
                                   'service', 'servicefilename', 'serviceprincipalnames', 'sharename', 'sidhistory',
                                   'source', 'sourceaddress', 'sourcenetworkaddress', 'status', 'subjectdomainname',
                                   'subjectlogonid', 'subjectusername', 'subjectusersid', 'targetusername',
                                   'ticketencryptiontype', 'ticketoptions', 'value', 'workstation', 'workstationname'],
              'extra_fields': ['servicename', 'taskname', 'qname', 'groupname', 'processname', 'parentintegritylevel',
                               'parentuser'],
              'syntax_errors': ['command', 'username', 'processcommandline', 'newprocessname', 'TargetProcessAddress']}
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
                    # manual check needed, still too many times that the AND condition fails
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
        if len(condition_parts) == 1:
            return True
        if len(condition_parts) == 3:
            if condition_parts[0] in ['1', 'one', '(1', '(one'] and condition_parts[1] == 'of':
                return True
        if len(condition_parts) > 2:
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
        start_string = '\t<if_group>windows</if_group>\n'
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
                    return start_string + '\t<field name="win.system.EventID">{}</field>'.format(query)
                else:
                    if event_id < 16:
                        if event_id > 9:
                            return '\t<if_group>sysmon_event_{}</if_group>'.format(event_id)
                        else:
                            return '\t<if_group>sysmon_event{}</if_group>'.format(event_id)
                    else:
                        return start_string + '\t<field name="win.system.EventID">^{}$</field>'.format(event_id)
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
        return start_string + 'Manual check needed! Doublecheck no EventID'

    def get_title(self, data, whitelist=False):
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


def write_file(output, filename, output_directory):
    with open(os.path.join(output_directory, filename.replace('.yml', '.xml')), 'w+') as file:
        for line in output:
            if re.match(r"reference", line) or re.match(r"field_rule", line):
                for item in output[line]:
                    file.write('{}\n'.format(item))
            else:
                file.write('{}\n'.format(output[line]))


# -----------  Print welcome ------------- #
def print_welcome():
    print("-" * 35, " SigWah ", "-" * 35)
    print(" " * 18, "Sigma rules converter for OSSEC and Wazuh", " " * 18)
    print("  ")
    print("Copyright by Sander Wiebing, Released under the GNU General Public License")
    print("Source code:  https://github.com/SanWieb/sigma-ossec")
    print("Version %s" % __version__)
    print("  ")
    print("Please report issues via https://github.com/SanWieb/sigma-ossec/issues")
    print("Feel free to contribute")
    print("NOTE - This script is in its very early stage")
    print("  ")
    print("-" * 80)


# -----------  Main ------------- #

def main():
    # print welcome
    print_welcome()
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='Path to scan for Sigma files', metavar='input_path')
    parser.add_argument('output', help='Path to output the Wazuh files', metavar='output_path')
    parser.add_argument('-r', help='Rule number to start with (adds up by 10)', metavar='int', default='250000')
    parser.add_argument('-t', help='The start modified date with time which files need to be processed, used to only process '
                                   'the files which changed', metavar='YYYY-MM-DD/HH:MM:SS',
                        default='1970-01-01/00:00:00')
    # Set variables
    args = parser.parse_args()
    input_directory = args.input
    output_directory = args.output
    try:
        rule_number = int(args.r)
    except Exception:
        print('Error: Invalid rule number')
        exit(0)
    date_list = re.split(':|-|/', args.t)
    try:
        dt = datetime.datetime(int(date_list[0]), int(date_list[1]), int(date_list[2]), int(date_list[3]), int(date_list[4]))
    except Exception:
        print("Error: Invalid modified date")
        exit(0)
    unix_time = (dt - datetime.datetime(1970, 1, 1)).total_seconds()
    # check if directory exists
    if not os.path.isdir(input_directory):
        print('Error: Invalid input directory')
        exit(0)
    if not os.path.isdir(output_directory):
        print('Error: Invalid output directory')
        exit(0)
    # loop all input files
    for filename in os.listdir(input_directory):
        if filename.endswith(".yml"):
            if unix_time < os.path.getmtime(os.path.join(input_directory, filename)):
                print(filename)
                document_data = read_file(os.path.join(input_directory, filename))
                sigmaConvert = SigWah(document_data, rule_number)
                output = sigmaConvert.get_output()
                write_file(output, filename, output_directory)
                rule_number += 10


if __name__ == '__main__':
    main()
