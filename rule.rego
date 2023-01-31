package app.rbac

import data.app.rbac.user_roles
import data.app.rbac.role_grants
import future.keywords.contains
import future.keywords.if
import future.keywords.in

import input

# By default, deny requests.
default allow = false

# More than one OR Condition for a variable `allow`

# Allow admins to do anything.
allow if user_is_admin


allow = true {
	some grant in user_is_granted

 	input.action == grant[action]
 	input.app_name == grant[app_name]
}

user_is_admin if "admin" in user_roles[input.user]

user_is_granted contains grant if {
 	some role in user_roles[input.user]
 	some grant in role_grants[role]
}

# # Allow the action if the user is granted permission to perform the action.
# allow {
#     # check for blacklisted grants for user
	
# 	# Find grants for the user.
# 	some grant in user_is_granted

# 	# Check if the grant permits the action. And Condition
# 	input.action == grant.action
# 	input.app_name == grant.app_name
# }

# # user_is_admin is true if...
# user_is_admin {

# 	# "admin" is the `i`-th element in the user->role mappings for the identified user.
# 	user_roles[input.user]== "admin"
# }

# # user_is_granted is a set of grants for the user identified in the request.
# # The `grant` will be contained if the set `user_is_granted` for every...
# user_is_granted contains grant if {

# 	# `role` assigned an element of the user_roles for this user...
# 	role := user_roles[input.user]

# 	# `grant` assigned a single grant from the grants list for 'role'...
# 	grant := role_grants[role]
# }





