#include "ldpd.h"


struct mpls_timer {
	struct event		ev;
	int					active;
	mpls_time_unit_enum	unit;
	int 				duration;
	int 				type;
	void 				*extra;
	mpls_cfg_handle		cfg;
	void (*handler)(mpls_timer_handle timer, void *extra, mpls_cfg_handle cfg);
};

static void setupTimeval(struct timeval *tv, mpls_time_unit_enum unit, int duration)
{
	if(!tv)
		return;

	timerclear(tv);

	if(unit == MPLS_UNIT_MICRO)
		tv->tv_usec = duration;
	else {
		int mult;
		if(unit == MPLS_UNIT_SEC)
			mult = 1;
		else if(mult == MPLS_UNIT_MIN)
			mult = 60;
		else if(mult == MPLS_UNIT_HOUR)
			mult = 3600;
		tv->tv_sec = duration * mult;
	}
}

static void timer_handler(int fd, short event, void *arg)
{
	struct mpls_timer *timer;

	timer = (struct mpls_timer *)arg;
	if(timer->active && timer->handler) {
		timer->handler(timer, timer->extra, timer->cfg);
		if(timer->type == MPLS_TIMER_REOCCURRING) {
			mpls_timer_start(0, timer, MPLS_TIMER_REOCCURRING);
		} else
			mpls_timer_stop(0, timer);
	}
}

mpls_timer_mgr_handle mpls_timer_open(mpls_instance_handle user_data)
{
	return 0xdeadbeef;
}

void mpls_timer_close(mpls_timer_mgr_handle handle)
{
}

mpls_timer_handle mpls_timer_create(mpls_timer_mgr_handle handle, mpls_time_unit_enum unit, int duration, void *extra, mpls_cfg_handle cfg, 
				void (*callback)(mpls_timer_handle timer, void *extra, mpls_cfg_handle cfg))
{
	struct mpls_timer *timer;

	timer = mpls_malloc(sizeof(struct mpls_timer));
	if(!timer)
		return NULL;

	timer->unit = unit;
	timer->duration = duration;
	timer->extra = extra;
	timer->cfg = cfg;
	timer->handler = callback;
	timer->active = 0;
	evtimer_set(&timer->ev, timer_handler, timer);

	return timer;
}

mpls_return_enum mpls_timer_modify(mpls_timer_mgr_handle handle, mpls_timer_handle timer, int duration)
{
	struct timeval  tv;

	if(!timer)
		return MPLS_FAILURE;

	timer->duration = duration;
	if(timer->active) {
		if(evtimer_del(&timer->ev) == -1)
			return MPLS_FAILURE;
		setupTimeval(&tv, timer->unit, timer->duration);
		if(evtimer_add(&timer->ev, &tv) == -1)
			return MPLS_FAILURE;
	}

	return MPLS_SUCCESS;
}

void mpls_timer_delete(mpls_timer_mgr_handle handle, mpls_timer_handle timer)
{
	if(timer)
		mpls_free(timer);
}

mpls_return_enum mpls_timer_start(mpls_timer_mgr_handle handle, mpls_timer_handle timer, mpls_timer_type_enum type)
{
	struct timeval tv;

	if(!timer)
		return MPLS_FAILURE;

	timer->type = type;
	timer->active = 1;

	setupTimeval(&tv, timer->unit, timer->duration);
	if(evtimer_add(&timer->ev, &tv) == -1)
		return MPLS_FAILURE;

	return MPLS_SUCCESS;
}

void mpls_timer_stop(mpls_timer_mgr_handle handle, mpls_timer_handle timer)
{
	if(timer && timer->active) {
		evtimer_del(&timer->ev);
		timer->active = 0;
	}
}
