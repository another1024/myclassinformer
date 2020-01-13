import re


def segs_by_name(name):
	ret = []
	segbase = get_first_seg()
	while segbase != BADADDR:
		if get_segm_name(segbase) == name:
			ret.append(segbase)
		segbase = get_next_seg(segbase)
	return ret


def hasrefto(addr):
	return get_first_cref_to(addr) != BADADDR or get_first_dref_to(addr) != BADADDR


def search_vtable(segname):

	segs = segs_by_name(segname)

	for seg_start in segs:
		seg_end = get_segm_end(seg_start)
		# first scan, make qword

		pattern = re.compile(r"dq\s+offset\s+(\w+)")
		cnt = 0
		vtbl = []
		classname = ''
		typemap = {}

		flag = 0
		addr = seg_start-8
		while addr < seg_end:
			addr += 8
			name = get_name(addr, 0)
			dname = demangle_name(name, 0)

			if dname and dname.find('vtable') != -1:
				flag = 1
				addr += 0x10
				classname = dname[dname.find('`vtable for\'')+len('`vtable for\''):]
			if flag:
				m = pattern.search(generate_disasm_line(addr, 0))
				if m:
					name = m.group(1)

					dname = demangle_name(name, 0)
					if dname is not None:
						name = dname
					if name is None:
						print 'Error at %x' % addr
					if name.find('::') != -1 and name.find('(') != -1:
						cnt += 1
						name = name.replace('~', 'Destruct')
						funcname = filter(str.isalnum, name)
						vtbl.append(funcname)
					elif name.find('pure_virtual') != -1:
						cnt += 1
						vtbl.append('pure_virtual_' + str(cnt))
				else:
					flag = 0

					if cnt != 0:
						cnt = 0
						print classname
						if classname != '' and len(vtbl) > 0:
							typename = classname + "Vtbl"
							if typename in typemap:
								typemap[typename] += 1
								typename += str(typemap[typename])
							else:
								typemap[typename] = 1
							sid = add_struc(-1, typename, 0)
							funcmap = {}
							for fn in vtbl:
								if fn in funcmap:
									funcmap[fn] += 1
									fn += str(funcmap[fn])
								else:
									funcmap[fn] = 1
								add_struc_member(sid, fn, -1, (FF_QWRD | FF_DATA), -1, 8)
						classname = ''
						vtbl = []


search_vtable('__const')
