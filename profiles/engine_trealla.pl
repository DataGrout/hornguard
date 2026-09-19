%% Engine manifest: what trealla defines.
%%
%% GENERATED on 2026-09-19 by running tools/engine_probe.pl inside trealla over the
%% candidate list from tools/gen_engine_manifest.pl. Regenerate with
%% `make manifests`.
%%
%% This records what EXISTS, never what is allowed. An indicator here
%% that no profile allows is still refused; the manifest only changes the
%% reason to a permission error and stops defer_unknown from deferring it.
%%
%% It describes the engine AS STARTED, with no libraries loaded. Libraries
%% widen what exists: Scryer reaches shell/1 and the sockets through
%% library(os) and library(sockets), which is why `loading` is pinned. A
%% host that loads libraries into author space has widened the engine, and
%% should regenerate this manifest with those libraries loaded.
%%
%% Capabilities this engine really exposes, all of them pinned:
%%   abolish/1                    database
%%   abolish/2                    database
%%   asserta/1                    database
%%   asserta/2                    database
%%   assertz/1                    database
%%   assertz/2                    database
%%   retract/1                    database
%%   retractall/1                 database
%%   erase/1                      destructive_state
%%   nb_setarg/3                  destructive_state
%%   absolute_file_name/2         filesystem
%%   absolute_file_name/3         filesystem
%%   delete_file/1                filesystem
%%   directory_files/2            filesystem
%%   exists_directory/1           filesystem
%%   exists_file/1                filesystem
%%   rename_file/2                filesystem
%%   working_directory/2          filesystem
%%   current_prolog_flag/2        flags_ops
%%   op/3                         flags_ops
%%   set_prolog_flag/2            flags_ops
%%   format/1                     format
%%   format/2                     format
%%   format/3                     format
%%   with_output_to/2             format
%%   consult/1                    loading
%%   load_files/1                 loading
%%   load_files/2                 loading
%%   make/0                       loading
%%   use_module/1                 loading
%%   use_module/2                 loading
%%   read_term_from_atom/3        parsing
%%   term_to_atom/2               parsing
%%   abort/0                      process
%%   getenv/2                     process
%%   halt/0                       process
%%   halt/1                       process
%%   process_create/3             process
%%   setenv/2                     process
%%   shell/1                      process
%%   shell/2                      process
%%   unsetenv/1                   process
%%   clause/2                     reflection
%%   clause/3                     reflection
%%   current_module/1             reflection
%%   current_op/3                 reflection
%%   current_predicate/1          reflection
%%   predicate_property/2         reflection
%%   prolog_load_context/2        reflection
%%   statistics/0                 reflection
%%   statistics/2                 reflection
%%   strip_module/3               reflection
%%   append/1                     streams
%%   close/1                      streams
%%   close/2                      streams
%%   current_input/1              streams
%%   current_output/1             streams
%%   flush_output/0               streams
%%   flush_output/1               streams
%%   get_byte/1                   streams
%%   get_byte/2                   streams
%%   get_char/1                   streams
%%   get_char/2                   streams
%%   listing/0                    streams
%%   listing/1                    streams
%%   nl/0                         streams
%%   nl/1                         streams
%%   open/3                       streams
%%   open/4                       streams
%%   peek_char/1                  streams
%%   peek_char/2                  streams
%%   portray_clause/1             streams
%%   portray_clause/2             streams
%%   print/1                      streams
%%   print/2                      streams
%%   put_byte/1                   streams
%%   put_byte/2                   streams
%%   put_char/1                   streams
%%   put_char/2                   streams
%%   read/1                       streams
%%   read/2                       streams
%%   read_term/2                  streams
%%   read_term/3                  streams
%%   see/1                        streams
%%   seeing/1                     streams
%%   seen/0                       streams
%%   set_stream/2                 streams
%%   stream_property/2            streams
%%   tab/1                        streams
%%   tab/2                        streams
%%   tell/1                       streams
%%   telling/1                    streams
%%   told/0                       streams
%%   with_output_to/2             streams
%%   write/1                      streams
%%   write/2                      streams
%%   write_canonical/1            streams
%%   write_canonical/2            streams
%%   write_term/2                 streams
%%   write_term/3                 streams
%%   writeln/1                    streams
%%   writeln/2                    streams
%%   writeq/1                     streams
%%   writeq/2                     streams
%%   engine_create/3              threads
%%   engine_create/4              threads
%%   engine_next/2                threads
%%   engine_yield/1               threads
%%   message_queue_create/1       threads
%%   message_queue_create/2       threads
%%   mutex_create/1               threads
%%   mutex_create/2               threads
%%   thread_create/2              threads
%%   thread_create/3              threads
%%   thread_self/1                threads
%%   thread_signal/2              threads
%%   sleep/1                      timing

:- multifile engine/2.

engine(trealla,!/0).
engine(trealla,(*->)/2).
engine(trealla,(',')/2).
engine(trealla,(->)/2).
engine(trealla,(;)/2).
engine(trealla,(<)/2).
engine(trealla,(=)/2).
engine(trealla,(=..)/2).
engine(trealla,(=:=)/2).
engine(trealla,(=<)/2).
engine(trealla,(==)/2).
engine(trealla,(=\=)/2).
engine(trealla,(>)/2).
engine(trealla,(>=)/2).
engine(trealla,?= / 2).
engine(trealla,(@<)/2).
engine(trealla,(@=<)/2).
engine(trealla,(@>)/2).
engine(trealla,(@>=)/2).
engine(trealla,(\+)/1).
engine(trealla,(\=)/2).
engine(trealla,(\==)/2).
engine(trealla,abolish/1).
engine(trealla,abolish/2).
engine(trealla,abort/0).
engine(trealla,absolute_file_name/2).
engine(trealla,absolute_file_name/3).
engine(trealla,acyclic_term/1).
engine(trealla,append/1).
engine(trealla,arg/3).
engine(trealla,asserta/1).
engine(trealla,asserta/2).
engine(trealla,assertz/1).
engine(trealla,assertz/2).
engine(trealla,atom/1).
engine(trealla,atom_chars/2).
engine(trealla,atom_codes/2).
engine(trealla,atom_concat/3).
engine(trealla,atom_length/2).
engine(trealla,atom_number/2).
engine(trealla,atomic/1).
engine(trealla,atomic_concat/3).
engine(trealla,atomic_list_concat/2).
engine(trealla,atomic_list_concat/3).
engine(trealla,bagof/3).
engine(trealla,between/3).
engine(trealla,call/1).
engine(trealla,call/2).
engine(trealla,call/3).
engine(trealla,call/4).
engine(trealla,call/5).
engine(trealla,call/6).
engine(trealla,call/7).
engine(trealla,call/8).
engine(trealla,call_cleanup/2).
engine(trealla,call_nth/2).
engine(trealla,callable/1).
engine(trealla,catch/3).
engine(trealla,char_code/2).
engine(trealla,clause/2).
engine(trealla,clause/3).
engine(trealla,close/1).
engine(trealla,close/2).
engine(trealla,compare/3).
engine(trealla,compound/1).
engine(trealla,consult/1).
engine(trealla,copy_term/2).
engine(trealla,copy_term_nat/2).
engine(trealla,current_input/1).
engine(trealla,current_module/1).
engine(trealla,current_op/3).
engine(trealla,current_output/1).
engine(trealla,current_predicate/1).
engine(trealla,current_prolog_flag/2).
engine(trealla,cyclic_term/1).
engine(trealla,delete_file/1).
engine(trealla,directory_files/2).
engine(trealla,duplicate_term/2).
engine(trealla,engine_create/3).
engine(trealla,engine_create/4).
engine(trealla,engine_next/2).
engine(trealla,engine_yield/1).
engine(trealla,erase/1).
engine(trealla,exists_directory/1).
engine(trealla,exists_file/1).
engine(trealla,fail/0).
engine(trealla,false/0).
engine(trealla,findall/3).
engine(trealla,findall/4).
engine(trealla,flatten/2).
engine(trealla,float/1).
engine(trealla,flush_output/0).
engine(trealla,flush_output/1).
engine(trealla,forall/2).
engine(trealla,format/1).
engine(trealla,format/2).
engine(trealla,format/3).
engine(trealla,functor/3).
engine(trealla,get_byte/1).
engine(trealla,get_byte/2).
engine(trealla,get_char/1).
engine(trealla,get_char/2).
engine(trealla,getenv/2).
engine(trealla,ground/1).
engine(trealla,halt/0).
engine(trealla,halt/1).
engine(trealla,ignore/1).
engine(trealla,integer/1).
engine(trealla,(is)/2).
engine(trealla,is_list/1).
engine(trealla,keysort/2).
engine(trealla,length/2).
engine(trealla,limit/2).
engine(trealla,listing/0).
engine(trealla,listing/1).
engine(trealla,load_files/1).
engine(trealla,load_files/2).
engine(trealla,make/0).
engine(trealla,message_queue_create/1).
engine(trealla,message_queue_create/2).
engine(trealla,msort/2).
engine(trealla,must_be/2).
engine(trealla,mutex_create/1).
engine(trealla,mutex_create/2).
engine(trealla,nb_setarg/3).
engine(trealla,nl/0).
engine(trealla,nl/1).
engine(trealla,nonvar/1).
engine(trealla,number/1).
engine(trealla,number_chars/2).
engine(trealla,number_codes/2).
engine(trealla,numlist/3).
engine(trealla,offset/2).
engine(trealla,once/1).
engine(trealla,op/3).
engine(trealla,open/3).
engine(trealla,open/4).
engine(trealla,peek_char/1).
engine(trealla,peek_char/2).
engine(trealla,portray_clause/1).
engine(trealla,portray_clause/2).
engine(trealla,predicate_property/2).
engine(trealla,print/1).
engine(trealla,print/2).
engine(trealla,process_create/3).
engine(trealla,prolog_load_context/2).
engine(trealla,put_byte/1).
engine(trealla,put_byte/2).
engine(trealla,put_char/1).
engine(trealla,put_char/2).
engine(trealla,random/1).
engine(trealla,random_between/3).
engine(trealla,rational/1).
engine(trealla,read/1).
engine(trealla,read/2).
engine(trealla,read_term/2).
engine(trealla,read_term/3).
engine(trealla,read_term_from_atom/3).
engine(trealla,rename_file/2).
engine(trealla,repeat/0).
engine(trealla,retract/1).
engine(trealla,retractall/1).
engine(trealla,see/1).
engine(trealla,seeing/1).
engine(trealla,seen/0).
engine(trealla,set_prolog_flag/2).
engine(trealla,set_stream/2).
engine(trealla,setenv/2).
engine(trealla,setof/3).
engine(trealla,setup_call_cleanup/3).
engine(trealla,shell/1).
engine(trealla,shell/2).
engine(trealla,sleep/1).
engine(trealla,sort/2).
engine(trealla,sort/4).
engine(trealla,split_string/4).
engine(trealla,statistics/0).
engine(trealla,statistics/2).
engine(trealla,stream_property/2).
engine(trealla,string/1).
engine(trealla,string_codes/2).
engine(trealla,string_concat/3).
engine(trealla,string_length/2).
engine(trealla,string_lower/2).
engine(trealla,string_upper/2).
engine(trealla,strip_module/3).
engine(trealla,sub_atom/5).
engine(trealla,sub_string/5).
engine(trealla,subsumes_term/2).
engine(trealla,succ/2).
engine(trealla,tab/1).
engine(trealla,tab/2).
engine(trealla,tell/1).
engine(trealla,telling/1).
engine(trealla,term_hash/2).
engine(trealla,term_singletons/2).
engine(trealla,term_to_atom/2).
engine(trealla,term_variables/2).
engine(trealla,term_variables/3).
engine(trealla,thread_create/2).
engine(trealla,thread_create/3).
engine(trealla,thread_self/1).
engine(trealla,thread_signal/2).
engine(trealla,throw/1).
engine(trealla,told/0).
engine(trealla,true/0).
engine(trealla,unifiable/3).
engine(trealla,unify_with_occurs_check/2).
engine(trealla,unsetenv/1).
engine(trealla,use_module/1).
engine(trealla,use_module/2).
engine(trealla,var/1).
engine(trealla,variant/2).
engine(trealla,with_output_to/2).
engine(trealla,working_directory/2).
engine(trealla,write/1).
engine(trealla,write/2).
engine(trealla,write_canonical/1).
engine(trealla,write_canonical/2).
engine(trealla,write_term/2).
engine(trealla,write_term/3).
engine(trealla,writeln/1).
engine(trealla,writeln/2).
engine(trealla,writeq/1).
engine(trealla,writeq/2).

%% Enforcement: like Scryer, Trealla has no in-engine caps the judge's host
%% can rely on. Compiled to WebAssembly it inherits the runtime's fuel and
%% memory limits, which is the strongest hermetic option here, but that is a
%% property of the deployment rather than of the engine, so the host attests
%% it.
enforcement(trealla, external).
