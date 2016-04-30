/* signal-session-manager.h
 *
 * Copyright (C) 2016 Patrick Griffis <tingping@tingping.se>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "signal-session.h"
#include "signal-address.h"

G_BEGIN_DECLS

#define SIGNAL_TYPE_SESSION_MANAGER (signal_session_manager_get_type())
G_DECLARE_FINAL_TYPE (SignalSessionManager, signal_session_manager, SIGNAL, SESSION_MANAGER, GObject)

GBytes *        signal_session_manager_new_exchange (SignalSessionManager *self,
                                                     SignalAddress        *address);

GBytes *        signal_session_manager_new_response (SignalSessionManager *self,
						                                         GBytes               *exchange,
                                                     SignalAddress        *address,
                                                     GError              **error);

SignalSession * signal_session_manager_new_session (SignalSessionManager *self,
                                                    GBytes               *response,
                                                    GError              **error);

G_END_DECLS
