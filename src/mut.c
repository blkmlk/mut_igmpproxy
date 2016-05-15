/**
mut.c - MUT implementation for Linux kernel
**/

#include "igmpproxy.h"

int insert_mut_dst(struct RouteTable *rt, uint32_t destination)
{
	struct mut_dst **m_dst;	

	if (rt == NULL) {
		return 1;
	}

	for(m_dst = &rt->mut_list; *m_dst != NULL; *m_dst = (*m_dst)->next) {
		if ((*m_dst)->ip == destination) {
			return 1;
		}
	}

	*m_dst = (struct mut_dst *) malloc(sizeof(struct mut_dst));
	(*m_dst)->ip = destination;
	(*m_dst)->activated = 0;
	(*m_dst)->next = NULL;

	return 0;
}

struct mut_dst *get_mut_dst(struct RouteTable *rt, uint32_t destination)
{
	struct mut_dst *i;

	if (rt == NULL) {
		return NULL;
	}

	for(i = rt->mut_list; i != NULL; i = i->next) {
		if (i->ip == destination) {
			return i;
		}
	}

	return NULL;
}

int delete_mut_dst(struct RouteTable *rt, uint32_t destination)
{
	struct mut_dst *i, **p;

	for(p = &rt->mut_list, i = *p; i != NULL; *p = i, i = i->next) {
		if (i->ip == destination) {
			if (*p == i) {
				(*p) = i->next;
			} else {
				(*p)->next = i->next;
			}
			free(i);

			return 0;
		}
	}

	return 1;
}

int has_any_dst(uint32_t group) {
	struct RouteTable *rt;
	int rc = 1;

	rt = findRoute(group);

	if (rt == NULL) {
		return rc;
	}

	if (rt->mut_list == NULL) {
		rc = 0;
	}

	return rc;
}

int activate_mut_rt(struct RouteTable *rt)
{
	struct mut_dst *i;
	int result;

	if (rt == NULL) {
		return 1;
	}

	for(i = rt->mut_list; i != NULL; i = i->next) {
		if (!i->activated) {
			result = add_mroute_mut_dst(rt->group, rt->originAddr, i->ip);
			i->activated = !result;
		}
	}

	return 0;
}

int leave_mut_dst(uint32_t group, uint32_t destination)
{
	struct RouteTable *rt;
	struct MRouteDesc desc;
	int rc = 1;

	rt = findRoute(group);

	if (rt == NULL) {
		return rc;
	}

	if (del_mroute_mut_dst(rt->group, rt->originAddr, destination) == 0) {
		rc = delete_mut_dst(rt, destination);
	}

	return rc;
}

int add_mroute_mut_dst(uint32_t group, uint32_t origin, uint32_t destination)
{
    struct mut_req req;
    int rc;

    req.group.s_addr  		= group;
    req.origin.s_addr    	= origin;
    req.destination.s_addr  = destination;

    rc = setsockopt(MRouterFD, IPPROTO_IP, MRT_MUT_ADD_DST, &req, sizeof(req));

    if (rc) {
        my_log(LOG_WARNING, errno, "MRT_MUT_ADD_DST");
    }

    return rc;
}

int del_mroute_mut_dst(uint32_t group, uint32_t origin, uint32_t destination)
{
    struct mut_req req;
    int rc;

    req.group.s_addr  		= group;
    req.origin.s_addr    	= origin;
    req.destination.s_addr 	= destination;

    rc = setsockopt(MRouterFD, IPPROTO_IP, MRT_MUT_DEL_DST, &req, sizeof(req));

    if (rc) {
        my_log(LOG_WARNING, errno, "MRT_MUT_DEL_DST");
    }

    return rc;
}


int sysctl_mut_init(int value)
{
	int rc;
	value = !!value;

	int name[] = {CTL_NET,NET_IPV4,NET_IPV4_MUT};
	int len = 3;

	rc = sysctl(name, len, 0, 0, &value, sizeof(value));

	return rc;
}