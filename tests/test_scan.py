import unittest
from unitgraph_guard.model import InputError, parse_snapshot, parse_policy, policy_default
from unitgraph_guard.scan import RULE_DESCRIPTIONS, evaluate, diff, is_enabled
from common import SECURE, rules, scan


class ScanTest(unittest.TestCase):
    def mutate(self, *add, remove=()):
        lines = [line for line in SECURE.splitlines() if not any(line.startswith(s + '=') for s in remove)]
        lines += list(add)
        return '\n'.join(lines) + '\n'

    def test_secure_clean(self): self.assertEqual(scan(), ())
    def test_root_without_user(self): self.assertIn('UG001', rules(self.mutate(remove=('User',))))
    def test_root_explicit(self): self.assertIn('UG001', rules(self.mutate('User=root')))
    def test_root_policy_allowed(self):
        policy = parse_policy({'schemaVersion':1,'allowedRootUnits':['demo.service']})
        self.assertNotIn('UG001', rules(self.mutate('User=root'),policy=policy))
    def test_dynamic_user_avoids_root(self):
        self.assertNotIn('UG001', rules(self.mutate('User=root','DynamicUser=yes')))
    def test_unsafe_exec_bypass(self): self.assertIn('UG002', rules(self.mutate('ExecStart=+/bin/true',remove=('ExecStart',))))
    def test_bypass_with_ignore_failure(self): self.assertIn('UG002', rules(self.mutate('ExecStart=-+/bin/true',remove=('ExecStart',))))
    def test_cap_ambient(self): self.assertIn('UG003', rules(self.mutate('AmbientCapabilities=CAP_SYS_ADMIN')))
    def test_cap_bounding(self): self.assertIn('UG003', rules(self.mutate('CapabilityBoundingSet=CAP_SYS_PTRACE')))
    def test_cap_safe(self): self.assertNotIn('UG003', rules(self.mutate('AmbientCapabilities=CAP_NET_BIND_SERVICE')))
    def test_secret_env(self): self.assertIn('UG004', rules(self.mutate('Environment=API_TOKEN=really-secret-value')))
    def test_secret_redacted(self):
        for record in scan(self.mutate('Environment=PASSWORD=supersecret123')):
            self.assertNotIn('supersecret123',str(record.to_dict()))
    def test_safe_env(self): self.assertNotIn('UG004', rules(self.mutate('Environment=COLOR=blue')))
    def test_rw_root(self): self.assertIn('UG005', rules(self.mutate('ReadWritePaths=/')))
    def test_rw_etc(self): self.assertIn('UG005', rules(self.mutate('ReadWritePaths=/etc')))
    def test_rw_state(self): self.assertNotIn('UG005', rules(self.mutate('ReadWritePaths=/var/lib/myservice')))
    def test_no_new_privileges(self): self.assertIn('UG006', rules(self.mutate('NoNewPrivileges=no')))
    def test_dynamic_implicit_no_new_privileges(self):
        self.assertNotIn('UG006', rules(self.mutate('NoNewPrivileges=no','DynamicUser=yes')))
    def test_protectsystem(self): self.assertIn('UG007', rules(self.mutate('ProtectSystem=full')))
    def test_protectsystem_dynamic(self): self.assertNotIn('UG007', rules(self.mutate('ProtectSystem=no','DynamicUser=yes')))
    def test_private_tmp(self): self.assertIn('UG008', rules(self.mutate('PrivateTmp=no')))
    def test_private_tmp_true(self): self.assertNotIn('UG008', rules())
    def test_protecthome(self): self.assertIn('UG009', rules(self.mutate('ProtectHome=no')))
    def test_protecthome_dynamic(self): self.assertNotIn('UG009', rules(self.mutate('ProtectHome=no','DynamicUser=yes')))
    def test_kernel_tunables(self): self.assertIn('UG010', rules(self.mutate('ProtectKernelTunables=no')))
    def test_kernel_modules(self): self.assertIn('UG011', rules(self.mutate('ProtectKernelModules=no')))
    def test_controlgroups(self): self.assertIn('UG012', rules(self.mutate('ProtectControlGroups=no')))
    def test_caps_unrestricted(self): self.assertIn('UG013', rules(self.mutate(remove=('CapabilityBoundingSet',))))
    def test_addressfamilies_unrestricted(self): self.assertIn('UG014', rules(self.mutate(remove=('RestrictAddressFamilies',))))
    def test_syscall_filter_absent(self): self.assertIn('UG015', rules(self.mutate(remove=('SystemCallFilter',))))
    def test_umask_world_writable(self): self.assertIn('UG016', rules(self.mutate('UMask=0000')))
    def test_umask_unsafe_0002(self): self.assertNotIn('UG016', rules(self.mutate('UMask=0002')))
    def test_shell_exec(self): self.assertIn('UG017', rules(self.mutate('ExecStart=/bin/sh -c echo',remove=('ExecStart',))))
    def test_script_in_tmp(self): self.assertIn('UG018', rules(self.mutate('ExecStart=/tmp/wrapper',remove=('ExecStart',))))
    def test_envfile_in_tmp(self): self.assertIn('UG018', rules(self.mutate('EnvironmentFile=-/tmp/secrets')))
    def test_execstart_missing(self): self.assertIn('UG019', rules(self.mutate(remove=('ExecStart',))))
    def test_execstart_restored_by_dropin(self):
        self.assertNotIn('UG019', rules(self.mutate(remove=('ExecStart',)),dropins=[{'name':'20.conf','content':'[Service]\nExecStart=/bin/service\n'}]))
    def test_invalid_booleans_rejected(self):
        for key in ('NoNewPrivileges','PrivateTmp','ProtectKernelTunables','ProtectKernelModules','ProtectControlGroups','DynamicUser'):
            with self.subTest(key=key), self.assertRaises(InputError): scan(self.mutate(f'{key}=perhaps'))
    def test_invalid_protect_modes(self):
        for key in ('ProtectHome','ProtectSystem'):
            with self.subTest(key=key), self.assertRaises(InputError): scan(self.mutate(f'{key}=invalid'))
    def test_invalid_umask(self):
        with self.assertRaises(InputError): scan(self.mutate('UMask=xyz'))
    def test_unclosed_shell_quote(self):
        with self.assertRaises(InputError): scan(self.mutate('ExecStart=/bin/bash -c "oops',remove=('ExecStart',)))
    def test_quoted_secret_env(self): self.assertIn('UG004', rules(self.mutate('Environment="API_KEY=has spaces"')))
    def test_unclosed_env_quote(self):
        with self.assertRaises(InputError): scan(self.mutate('Environment="oops'))
    def test_same_rule_single_finding(self):
        a = scan(self.mutate('ReadWritePaths=/ /'))
        self.assertEqual([x.rule_id for x in a].count('UG005'),1)
    def test_duplicate_findings_stable(self):
        a = scan(self.mutate('Environment=TOKEN=first'))
        b = scan(self.mutate('Environment=TOKEN=second'))
        self.assertEqual({x.fingerprint for x in a},{x.fingerprint for x in b})
    def test_order_independent(self):
        a = self.mutate('Environment=LOG_LEVEL=debug', 'ReadWritePaths=/etc')
        b = self.mutate('ReadWritePaths=/etc', 'Environment=LOG_LEVEL=debug')
        self.assertEqual([x.to_dict() for x in scan(a)], [x.to_dict() for x in scan(b)])
    def test_all_rules_registered(self): self.assertEqual(len(RULE_DESCRIPTIONS), 24)
    def test_empty_boolean(self): self.assertFalse(is_enabled('', 'X'))


class GraphTest(unittest.TestCase):
    def snapshot(self, deps):
        return parse_snapshot({'schemaVersion':1, 'units':[
            {'name':n+'.service', 'content':SECURE.replace('[Service]',f'[Unit]\n{dep}\n[Service]')}
            for n,dep in deps.items()]})

    def test_simple_after_no_cycle(self):
        self.assertNotIn('UG020', {x.rule_id for x in evaluate(self.snapshot({'a':'After=b.service','b':''}),policy_default())})

    def test_after_cycle(self):
        result=evaluate(self.snapshot({'a':'After=b.service','b':'After=a.service'}),policy_default())
        self.assertEqual([x.rule_id for x in result].count('UG020'),1)

    def test_self_cycle(self):
        result=evaluate(self.snapshot({'a':'After=a.service'}),policy_default())
        self.assertIn('UG020',{x.rule_id for x in result})

    def test_before_cycle(self):
        result=evaluate(self.snapshot({'a':'Before=b.service','b':'Before=a.service'}),policy_default())
        self.assertIn('UG020',{x.rule_id for x in result})

    def test_disjoint_cycles(self):
        result=evaluate(self.snapshot({'a':'After=b.service','b':'After=a.service','c':'After=d.service','d':'After=c.service'}),policy_default())
        self.assertEqual([x.rule_id for x in result].count('UG020'),2)

    def test_strict_missing_deps(self):
        policy=parse_policy({'schemaVersion':1,'strictDependencies':True})
        result=evaluate(self.snapshot({'a':'Requires=absent.service'}),policy)
        self.assertIn('UG021',{x.rule_id for x in result})

    def test_unstrict_missing_deps(self):
        result=evaluate(self.snapshot({'a':'Requires=absent.service'}),policy_default())
        self.assertNotIn('UG021',{x.rule_id for x in result})

    def test_forbidden_dep(self):
        policy=parse_policy({'schemaVersion':1,'forbiddenDependencies':['rescue.target']})
        result=evaluate(self.snapshot({'a':'Wants=rescue.target'}),policy)
        self.assertIn('UG022',{x.rule_id for x in result})

    def test_root_dependency_critical(self):
        policy=parse_policy({'schemaVersion':1,'criticalUnits':['a.service']})
        s=self.snapshot({'a':'Requires=b.service','b':''})
        target={u.name:{'name':u.name,'content':u.content} for u in s.units}
        target['b.service']['content']=SECURE.replace('User=service','User=root')
        result=evaluate(parse_snapshot({'schemaVersion':1,'units':list(target.values())}),policy)
        self.assertIn('UG023',{x.rule_id for x in result})

    def test_notcritical_root_dependency(self):
        s=self.snapshot({'a':'Requires=b.service','b':''})
        data=[{'name':u.name,'content':u.content.replace('User=service','User=root') if u.name=='b.service' else u.content} for u in s.units]
        result=evaluate(parse_snapshot({'schemaVersion':1,'units':data}),policy_default())
        self.assertNotIn('UG023',{x.rule_id for x in result})

    def test_conflicting_requires(self):
        result=evaluate(self.snapshot({'a':'Requires=b.service\nConflicts=b.service','b':''}),policy_default())
        self.assertIn('UG024',{x.rule_id for x in result})

    def test_compare_new_only(self):
        base=scan()
        changed=scan(SECURE.replace('User=service','User=root'))
        part=diff(base,changed)
        self.assertEqual(len(part['new']),1)
        self.assertEqual(len(part['resolved']),0)

    def test_compare_resolved(self):
        part=diff(scan(SECURE.replace('User=service','User=root')),scan())
        self.assertEqual(len(part['resolved']),1)
        self.assertEqual(len(part['new']),0)

    def test_compare_persistent(self):
        a=scan(SECURE.replace('User=service','User=root'))
        part=diff(a,a)
        self.assertEqual(len(part['persistent']),1)

class AdditionalEdgeCases(unittest.TestCase):
    def test_private_tmp_disconnected(self):
        self.assertNotIn('UG008', rules(SECURE.replace('PrivateTmp=yes','PrivateTmp=disconnected')))

    def test_dynamic_tmp_implicit(self):
        content=SECURE.replace('User=service','DynamicUser=yes').replace('PrivateTmp=yes','')
        self.assertNotIn('UG008', rules(content))

    def test_capability_empty_bounding_set_is_restrictive(self):
        content=SECURE.replace('CapabilityBoundingSet=CAP_NET_BIND_SERVICE','CapabilityBoundingSet=')
        self.assertNotIn('UG013', rules(content))

    def test_rw_traversal_normalized(self):
        self.assertIn('UG005', rules(SECURE+'ReadWritePaths=/var/../\n'))

    def test_bad_environment_key(self):
        with self.assertRaises(InputError):scan(SECURE+'Environment="BAD-KEY=secret"\n')

class AdversarialRuleTest(unittest.TestCase):
    def test_plus_in_binary_path_is_not_privilege_bypass(self):
        self.assertNotIn('UG002', rules(SECURE.replace('/usr/local/bin/service','/opt/my+service/bin/service')))

    def test_bash_lc_is_shell(self):
        self.assertIn('UG017', rules(SECURE.replace('ExecStart=/usr/local/bin/service','ExecStart=/bin/bash -lc echo')))

    def test_full_bounding_reset_is_unrestricted(self):
        self.assertIn('UG013', rules(SECURE.replace('CapabilityBoundingSet=CAP_NET_BIND_SERVICE','CapabilityBoundingSet=~')))

    def test_credential_key_stable_and_redacted(self):
        a = scan(SECURE + 'Environment=PRIVATE_KEY="secret-one"\n')
        b = scan(SECURE + 'Environment=PRIVATE_KEY="different-secret"\n')
        self.assertEqual([x.to_dict() for x in a], [x.to_dict() for x in b])

    def test_system_call_filter_empty_is_absent(self):
        self.assertIn('UG015', rules(SECURE.replace('SystemCallFilter=@system-service','SystemCallFilter=')))

    def test_critical_root_dep_does_not_leak_exec(self):
        policy = parse_policy({'schemaVersion':1,'criticalUnits':['app.service']})
        src = parse_snapshot({'schemaVersion':1,'units':[
            {'name':'app.service','content':'[Unit]\nWants=root.service\n'+SECURE},
            {'name':'root.service','content':SECURE.replace('User=service','User=root').replace('ExecStart=/usr/local/bin/service','ExecStart=/bin/true --token=secret-must-not-be-exposed')}]})
        rows = evaluate(src,policy)
        self.assertIn('UG023',{r.rule_id for r in rows})
        self.assertNotIn('secret-must-not-be-exposed',str([r.to_dict() for r in rows]))
