package malloy_query_execute

import rego.v1

default allow := false

user_exists {
    data[input.user]
}

all_sources_exist {
    not missing_sources
}

missing_sources[s] {
    some i
    s := input.sources[i]
    not s == data[input.user].sources[_]
}

allow if {
    user_exist
    all_sources_exist
}