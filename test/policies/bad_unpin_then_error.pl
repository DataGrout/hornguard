%% Reopens a class, then fails validation. Loading it must change nothing.
backend(swi).
unpin(reflection).
profiles([iso, no_such_profile]).
