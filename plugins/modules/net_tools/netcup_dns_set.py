#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2021 DasSkelett <dasskelett@gmail.com>
# (c) 2018 Nicolai Buchwitz <nb@tipi-net.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
---
module: netcup_dns_set
notes: []
short_description: manage Netcup DNS records
description:
  - "Manages DNS records via the Netcup API in a more declarative fashion than the netcup_dns module. Allows you to specifiy a state (list of records) which the domain should possess, new records are created as needed and obsolete records will be removed."
options:
  api_key:
    description:
      - API key for authentication, must be obtained via the netcup CCP (U(https://ccp.netcup.net))
    required: True
    type: str
  api_password:
    description:
      - API password for authentication, must be obtained via the netcup CCP (https://ccp.netcup.net)
    required: True
    type: str
  customer_id:
    description:
      - Netcup customer id
    required: True
    type: int
  domain:
    description:
      - Domainname the records should be added / removed
    required: True
    type: str
  record_set:
    description:
      - List of record dicts that should be present in the domain zone
    required: True
    type: list
    elements: dict
    suboptions:
      record:
        description:
          - Record to add or delete, supports wildcard (*). Default is C(@) (e.g. the zone name)
        default: "@"
        aliases: [ name ]
        required: False
        type: str
      type:
        description:
          - Record type
        choices: ['A', 'AAAA', 'MX', 'CNAME', 'CAA', 'SRV', 'TXT', 'TLSA', 'NS', 'DS', 'OPENPGPKEY', 'SMIMEA']
        required: True
        type: str
      value:
        description:
          - Record value
        required: true
        type: str
      priority:
        description:
          - Record priority. Required for C(type=MX)
        required: False
        type: int

  
requirements:
  - "nc-dnsapi >= 0.1.5"
author: "DasSkelett (@DasSkelett)"

'''

EXAMPLES = '''
- name: Set zone to have two AAAA, one A and one MX record
  community.general.netcup_dns_set:
    api_key: "..."
    api_password: "..."
    customer_id: "..."
    domain: "example.com"
    record_set:
      - name: "mail"
        type: "AAAA"
        value: "2001:db8::5"
      - name: "mail"
        type: "AAAA"
        value: "2001:db8::6"
      - name: "mail"
        type: "A"
        value: "10.79.87.4"
      - name: "@"
        type: "MX"
        value: "mail.example.com"
        priority: 10

- name: Delete all records from zone (DANGEROUS!)
  community.general.netcup_dns_set:
    api_key: "..."
    api_password: "..."
    customer_id: "..."
    domain: "example.com"
    record_set: []
'''

RETURN = '''
removed:
    description: list containing all removed records
    returned: success
    type: complex
    contains:
        name:
            description: the record name
            returned: success
            type: str
            sample: fancy-hostname
        type:
            description: the record type
            returned: succcess
            type: str
            sample: A
        value:
            description: the record destination
            returned: success
            type: str
            sample: 127.0.0.1
        priority:
            description: the record priority (only relevant if type=MX)
            returned: success
            type: int
            sample: 0
        id:
            description: internal id of the record
            returned: success
            type: int
            sample: 12345
updated:
    description: list containing all changed and added records
    returned: success
    type: complex
    contains:
        name:
            description: the record name
            returned: success
            type: str
            sample: fancy-hostname
        type:
            description: the record type
            returned: succcess
            type: str
            sample: A
        value:
            description: the record destination
            returned: success
            type: str
            sample: 127.0.0.1
        priority:
            description: the record priority (only relevant if type=MX)
            returned: success
            type: int
            sample: 0
        id:
            description: internal id of the record
            returned: success
            type: int
            sample: 12345
records:
    description: list containing all records
    returned: success
    type: complex
    contains:
        name:
            description: the record name
            returned: success
            type: str
            sample: fancy-hostname
        type:
            description: the record type
            returned: succcess
            type: str
            sample: A
        value:
            description: the record destination
            returned: success
            type: str
            sample: 127.0.0.1
        priority:
            description: the record priority (only relevant if type=MX)
            returned: success
            type: int
            sample: 0
        id:
            description: internal id of the record
            returned: success
            type: int
            sample: 12345
'''

import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

NCDNSAPI_IMP_ERR = None
try:
    import nc_dnsapi
    from nc_dnsapi import DNSRecord

    HAS_NCDNSAPI = True
except ImportError:
    NCDNSAPI_IMP_ERR = traceback.format_exc()
    HAS_NCDNSAPI = False


def main():
    module = AnsibleModule(
        argument_spec=dict(
            api_key=dict(required=True, no_log=True),
            api_password=dict(required=True, no_log=True),
            customer_id=dict(required=True, type='int'),
            domain=dict(required=True),

            record_set=dict(
                required=True, type='list', elements='dict',
                options=dict(
                    record=dict(required=False, aliases=['name'], default='@'),
                    type=dict(required=True, choices=['A', 'AAAA', 'MX', 'CNAME', 'CAA', 'SRV', 'TXT', 'TLSA', 'NS', 'DS', 'OPENPGPKEY', 'SMIMEA']),
                    value=dict(required=True),
                    priority=dict(required=False, type='int'),
                ),
                required_if=[
                  ('type', 'MX', ['priority']),
                ],
            ),
        ),
        supports_check_mode=True
    )

    if not HAS_NCDNSAPI:
        module.fail_json(msg=missing_required_lib('nc-dnsapi'), exception=NCDNSAPI_IMP_ERR)

    api_key = module.params.get('api_key')
    api_password = module.params.get('api_password')
    customer_id = module.params.get('customer_id')
    domain = module.params.get('domain')
    record_set = module.params.get('record_set')

    has_changed = False
    all_records = []
    try:
        with nc_dnsapi.Client(customer_id, api_key, api_password) as api:
            all_records = api.dns_records(domain)
            record_set = [ DNSRecord(
                    record.get('record'), record.get('type'), record.get('value'), priority=record.get('priority')
                ) for record in record_set ]

            updated = []
            obsolete = []
            for record in record_set:
                if record not in all_records:
                    updated.append(record)

            for existing_record in all_records:
                if existing_record not in record_set:
                    obsolete.append(existing_record)

            if len(obsolete) > 0:
                if not module.check_mode:
                    api.delete_dns_records(domain, obsolete)
                    pass
                has_changed = True
            if len(updated) > 0:
                if not module.check_mode:
                    all_records = api.update_dns_records(domain, updated)
                    pass
                has_changed = True

            module.exit_json(changed=has_changed, result={
                "removed": [record_data(r) for r in obsolete],
                "updated": [record_data(r) for r in updated],
                "records": [record_data(r) for r in all_records]
            })

    except Exception as ex:
        module.fail_json(msg=str(ex))

    module.exit_json(changed=has_changed, result={"records": [record_data(r) for r in all_records]})


def record_data(r):
    return {"name": r.hostname, "type": r.type, "value": r.destination, "priority": r.priority, "id": r.id}


if __name__ == '__main__':
    main()
