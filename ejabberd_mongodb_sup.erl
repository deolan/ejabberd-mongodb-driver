%%%----------------------------------------------------------------------
%%% File    : ejabberd_mongodb_sup.erl
%%% @author Andrei Leontev <andrei.leontev@protonmail.ch>
%%% @doc
%%% implements MongoDb database connection options
%%% @end
%%% Created : 12 Nov 2016 by Andrei Leontev <andrei.leontev@protonmail.ch>
%%%
%%% Copyright (C) 2016    Andrei Leontev
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License along
%%% with this program; if not, write to the Free Software Foundation, Inc.,
%%% 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
%%%
%%%----------------------------------------------------------------------

-module(ejabberd_mongodb_sup).

-behaviour(ejabberd_config).
-author('andrei.leontev@protonmail.ch').

-export([start/0, start_link/0, init/1, get_pids/0,
	 transform_options/1, get_random_pid/0, get_random_pid/1,
	 opt_type/1]).

-include("ejabberd.hrl").
-include("logger.hrl").

-define(DEFAULT_POOL_SIZE, 10).
-define(DEFAULT_MONGODB_START_INTERVAL, 30). % 30 seconds
-define(DEFAULT_MONGODB_HOST, "127.0.0.1").
-define(DEFAULT_MONGODB_PORT, 27017).
-define(DEFAULT_MONGODB_DATABASE, <<"test">>).

% time to wait for the supervisor to start its child before returning
% a timeout error to the request
-define(CONNECT_TIMEOUT, 500). % milliseconds

start() ->
    case lists:any(
	   fun(Host) ->
		   is_mongodb_configured(Host)
	   end, ?MYHOSTS) of
	true ->
      ejabberd:start_app(bson),
      ejabberd:start_app(crypto),
	    ejabberd:start_app(mongodb),
            do_start();
	false ->
	    ok
    end.

is_mongodb_configured(Host) ->
    ServerConfigured = ejabberd_config:get_option(
			 {mongodb_server, Host},
			 fun(_) -> true end, false),
    PortConfigured = ejabberd_config:get_option(
		       {mongodb_port, Host},
		       fun(_) -> true end, false),
    AuthConfigured = lists:member(
		       ejabberd_auth_mongodb,
		       ejabberd_auth:auth_modules(Host)),
    Modules = ejabberd_config:get_option(
		{modules, Host},
		fun(L) when is_list(L) -> L end, []),
    ModuleWithMongoDBConfigured = lists:any(
				   fun({Module, Opts}) ->
					   gen_mod:db_type(Host, Opts, Module) == mongodb
				   end, Modules),
    ServerConfigured or PortConfigured
	or AuthConfigured or ModuleWithMongoDBConfigured.

do_start() ->
    SupervisorName = ?MODULE,
    ChildSpec =
	{SupervisorName,
	 {?MODULE, start_link, []},
	 transient,
	 infinity,
	 supervisor,
	 [?MODULE]},
    case supervisor:start_child(ejabberd_sup, ChildSpec) of
	{ok, _PID} ->
	    ok;
	_Error ->
	    ?ERROR_MSG("Start of supervisor ~p failed:~n~p~nRetrying...~n",
                       [SupervisorName, _Error]),
            timer:sleep(5000),
	    start()
    end.

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    PoolSize = get_pool_size(),
    StartInterval = get_start_interval(),
    Server = get_mongodb_server(),
    Port = get_mongodb_port(),
    CACertFile = get_mongodb_cacertfile(),
    Database = get_mongodb_database(),
    Username = get_mongodb_username(),
    Password = get_mongodb_password(),
    Options = lists:filter(
		fun(X) -> X /= nil end,
		[auto_reconnect,
		 {keepalive, true},
		 if CACertFile /= nil -> {cacertfile ,CACertFile};
		    true -> nil
		 end,
		 if (Username /= nil) and (Password /= nil) ->
			 {credentials, Username, Password};
		    true -> nil
		 end
		]),
    {ok, {{one_for_one, PoolSize*10, 1},
	  lists:map(
	    fun(I) ->
		    {ejabberd_mongodb:get_proc(I),
		     {ejabberd_mongodb, start_link,
                      [I, Server, Port, Database, StartInterval*1000, Options]},
		     transient, 2000, worker, [?MODULE]}
	    end, lists:seq(1, PoolSize))}}.

get_start_interval() ->
    ejabberd_config:get_option(
      mongodb_start_interval,
      fun(N) when is_integer(N), N >= 1 -> N end,
      ?DEFAULT_MONGODB_START_INTERVAL).

get_pool_size() ->
    ejabberd_config:get_option(
      mongodb_pool_size,
      fun(N) when is_integer(N), N >= 1 -> N end,
      ?DEFAULT_POOL_SIZE).

get_mongodb_server() ->
    ejabberd_config:get_option(
      mongodb_server,
      fun(S) ->
	      binary_to_list(iolist_to_binary(S))
      end, ?DEFAULT_MONGODB_HOST).

get_mongodb_cacertfile() ->
    ejabberd_config:get_option(
      mongodb_cacertfile,
      fun(S) ->
	      binary_to_list(iolist_to_binary(S))
      end, nil).

get_mongodb_database() ->
    ejabberd_config:get_option(
      mongodb_database,
      fun(S) ->
        binary_to_list(iolist_to_binary(S))
      end, ?DEFAULT_MONGODB_DATABASE).

get_mongodb_username() ->
    ejabberd_config:get_option(
      mongodb_username,
      fun(S) ->
	      binary_to_list(iolist_to_binary(S))
      end, nil).

get_mongodb_password() ->
    ejabberd_config:get_option(
      mongodb_password,
      fun(S) ->
	      binary_to_list(iolist_to_binary(S))
      end, nil).

get_mongodb_port() ->
    ejabberd_config:get_option(
      mongodb_port,
      fun(P) when is_integer(P), P > 0, P < 65536 -> P end,
      ?DEFAULT_MONGODB_PORT).

get_pids() ->
    [ejabberd_mongodb:get_proc(I) || I <- lists:seq(1, get_pool_size())].

get_random_pid() ->
    get_random_pid(p1_time_compat:monotonic_time()).

get_random_pid(Term) ->
    I = erlang:phash2(Term, get_pool_size()) + 1,
    ejabberd_mongodb:get_proc(I).

transform_options(Opts) ->
    lists:foldl(fun transform_options/2, [], Opts).

transform_options({mongodb_server, {S, P}}, Opts) ->
    [{mongodb_server, S}, {mongodb_port, P}|Opts];
transform_options(Opt, Opts) ->
    [Opt|Opts].

opt_type(modules) -> fun (L) when is_list(L) -> L end;
opt_type(mongodb_pool_size) ->
    fun (N) when is_integer(N), N >= 1 -> N end;
opt_type(mongodb_port) -> fun (_) -> true end;
opt_type(mongodb_server) -> fun (_) -> true end;
opt_type(mongodb_start_interval) ->
    fun (N) when is_integer(N), N >= 1 -> N end;
opt_type(mongodb_cacertfile) -> fun iolist_to_binary/1;
opt_type(mongodb_database) -> fun iolist_to_binary/1;
opt_type(mongodb_username) -> fun iolist_to_binary/1;
opt_type(mongodb_password) -> fun iolist_to_binary/1;
opt_type(_) ->
    [modules, mongodb_pool_size, mongodb_port, mongodb_server,
     mongodb_start_interval, mongodb_cacertfile, mongodb_database, 
     mongodb_username, mongodb_password].
