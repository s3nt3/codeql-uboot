import cpp

from MacroInvocation i
where i.getMacro().getName().regexpMatch("ntoh(s|l|ll)")
select i
