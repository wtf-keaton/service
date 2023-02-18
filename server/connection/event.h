#pragma once
#include <mutex>
#include <vector>
#include <functional>
#include <utility>

namespace fusion::server
{
	template<typename... Args>
	class c_events
	{
		using function_type = std::function<void( Args... )>;

		std::mutex m_event_lock;
		std::vector<function_type> m_functions;

	public:
		void add( const function_type& function )
		{
			std::lock_guard<std::mutex> lock( m_event_lock );

			m_functions.emplace_back( function );
		}

		void call( Args... args )
		{
			std::lock_guard<std::mutex> lock( m_event_lock );

			for ( const auto& functions : m_functions )
			{
				if ( functions )
				{
					functions( std::forward<Args>( args )... );
				}
			}
		}
	};
}