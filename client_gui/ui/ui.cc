#include "ui.hh"
#include "../imgui/imgui.h"
#include "../imgui/imgui_internal.h"

#include "../xorstr/xorstr.h"

#include "../threads.h"

void ui::render( )
{
	if ( !globals.active ) return;
	/*if ( !globals.is_loaded )
	{
		fusion::syscall::exit( );
	}*/
	ImGui::SetNextWindowPos( ImVec2( 0, 0 ), ImGuiCond_Always );
	ImGui::SetNextWindowSize( ImVec2( window_size.x, window_size.y ) );

	static char key[ 256 ];

	ImGui::Begin( window_title, &globals.active, window_flags );
	{
		auto draw = ImGui::GetWindowDrawList( );
		auto pos = ImGui::GetWindowPos( );

		static bool once = false;
		if ( !once )
		{
			std::thread thread( initializing_test );
			thread.detach( );

			once = true;
		}
		// line
		draw->AddRectFilled( pos, pos + ImVec2( window_size.x, 3 ), ImGui::GetColorU32( ImGuiCol_ButtonHovered ) );

		switch ( page )
		{
			case e_page_state::_loading_bar:
			{
				auto front = ImGui::GetForegroundDrawList( ); // also you can use GetWindowDrawList() or GetBackgroundDrawList()
				ImVec2 center = ImVec2( ImGui::GetIO( ).DisplaySize.x / 2.f, 100 );
				static ImColor fore_color( 200, 20, 20, 255 );
				static ImColor back_color( 200, 20, 20, 40 );
				static float arc_size = 0.45f; // 0.f < x < 2.f
				static float radius = 35.f;
				static float thickness = 4.f;

				// Animation
				static float position = 0.f;
				position = ImLerp( position, IM_PI * 2.f, ImGui::GetIO( ).DeltaTime * 2.3f );

				// Background
				front->PathClear( );
				front->PathArcTo( center, radius, 0.f, 2.f * IM_PI + 1, 42.f );
				front->PathStroke( IM_COL32( 35, 67, 108, 255 ), 0, thickness );

				// Foreground
				front->PathClear( );
				front->PathArcTo( center, radius, IM_PI * 1.5f + position, IM_PI * ( 1.5f + arc_size ) + position, 40.f );
				front->PathStroke( ImGui::GetColorU32( ImGuiCol_ButtonActive ), 0, thickness );

				// Reset animation
				if ( position >= IM_PI * 1.90f )
					position = 0.f;

				ImGui::SetCursorPos( ImVec2( ( window_size.x - ImGui::CalcTextSize( globals.status ).x ) / 2 - 9, 160 ) );
				ImGui::Text( globals.status );

				break;
			}
			case e_page_state::_auth:
			{
				ImGui::SetCursorPos( ImVec2( ( window_size.x - 280 ) / 2, 60 ) );
				ImGui::PushItemWidth( 280 );
				ImGui::InputTextWithHint( _( "##key" ), _( "Your key" ), key, ARRAYSIZE( key ) );

				ImGui::SetCursorPos( ImVec2( ( window_size.x - 180 ) / 2, 200 ) );
				if ( ImGui::Button( _( "Log in" ), ImVec2( 180, 30 ) ) )
				{
					request_t request{};

					request.active_hwid_hash = 0xfffff;
					request.request_type = e_request_type::_authorization;

					strcpy_s( request.key, key );
					fusion::client::send( &request, sizeof request );

					uintptr_t result = 0;
					fusion::client::recv( &result, sizeof result );
					switch ( result )
					{
						case e_request_result::_success: page = e_page_state::_inject; break;
						case e_request_result::_error_freezed: strcpy_s( globals.error, _( "Cheat freezed" ) ); page = e_page_state::_error; break;
						case e_request_result::_error_banned: strcpy_s( globals.error, _( "Subscribe banned" ) ); page = e_page_state::_error; break;
						case e_request_result::_error_hwid_missmatch: strcpy_s( globals.error, _( "HWID Missmatch" ) ); page = e_page_state::_error; break;
						case e_request_result::_error_subscribe_end : strcpy_s( globals.error, _( "Subscribe expired" ) ); page = e_page_state::_error; break;
						case e_request_result::_error_userkey: strcpy_s( globals.error, _( "Invalid key" ) ); page = e_page_state::_error; break;
					}
				}
				break;
			}
			case e_page_state::_inject:
			{
				static bool once = false;
				static user_info_request_t user_info;

				if ( !once )
				{
					request_t request{};
					request.active_hwid_hash = 0xffff;
					request.request_type = e_request_type::_get_user_information;
					strcpy_s( request.key, key );

					fusion::client::send( &request, sizeof request );

					fusion::client::recv( &user_info, sizeof( user_info ) );

					strcpy_s( globals.process_name, user_info.game_process );

					once = true;
				}
				ImGui::SetCursorPos( ImVec2( 60, 50 ) );
				ImGui::BeginGroup( );
				ImGui::Text( _( "Product:" ) ); ImGui::SameLine( 0, 140 ); ImGui::Text( user_info.game );
				ImGui::NewLine( );
				ImGui::Text( _( "Expire:" ) ); ImGui::SameLine( 0, 150 ); ImGui::Text( user_info.end_date );
				ImGui::NewLine( );
				ImGui::Text( _( "Process:" ) ); ImGui::SameLine( 0, 150 ); ImGui::Text( globals.process_name );
				ImGui::EndGroup( );

				ImGui::SetCursorPos( ImVec2( ( window_size.x - 180 ) / 2, 200 ) );
				switch ( globals.inject_status )
				{
					case e_injection_state::_none:
					{
						if ( ImGui::Button( _( "Launch" ), ImVec2( 180, 30 ) ) )
						{
							globals.inject_status = e_injection_state::_loading;
							request_t request{};

							request.active_hwid_hash = 0xfffff;
							request.request_type = e_request_type::_get_binary;
							request.binary_type = e_binary_type::_cheat;
							strcpy_s( request.key, key );

							fusion::client::send( &request, sizeof request );

							std::thread injection( inject_thread );
							injection.detach( );

						}
						break;
					}
					case e_injection_state::_loading:
					{
						ImGui::PushItemFlag( ImGuiItemFlags_Disabled, true );
						ImGui::Button( _( "Loading" ), ImVec2( 180, 30 ) );
						ImGui::PopItemFlag( );
						break;
					}
					case e_injection_state::_parse_imports:
					{
						ImGui::PushItemFlag( ImGuiItemFlags_Disabled, true );
						ImGui::Button( _( "Parsing imports" ), ImVec2( 180, 30 ) );
						ImGui::PopItemFlag( );
						break;
					}
					case e_injection_state::_progress:
					{			
						ImGui::ProgressBar( globals.value, ImVec2( 180, 30 ) );

						break;
					}		
					case e_injection_state::_injection:
					{
						ImGui::PushItemFlag( ImGuiItemFlags_Disabled, true );
						ImGui::Button( _( "Injection" ), ImVec2( 180, 30 ) );
						ImGui::PopItemFlag( );
						break;
					}				
					case e_injection_state::_injected:
					{
						ImGui::PushItemFlag( ImGuiItemFlags_Disabled, true );
						ImGui::Button( _( "Injected" ), ImVec2( 180, 30 ) );
						ImGui::PopItemFlag( );
						break;
					}
				}

			
				break;
			}
			case e_page_state::_error:
			{
				ImGui::SetCursorPos( ImVec2( ( window_size.x - ImGui::CalcTextSize( globals.error ).x ) / 2, ImGui::GetIO( ).DisplaySize.y / 2.f ) );
				ImGui::TextColored( ImVec4( 1.f, 0.f, 0.f, 1.f ), "%s", globals.error );

				if ( globals.is_loaded ) 	fusion::driver::unload( );
				break;
			}
		}
	}
	ImGui::End( );
}

void ui::init( LPDIRECT3DDEVICE9 device )
{
	dev = device;

	// colors
	ImGui::StyleColorsDark( );

	if ( window_pos.x == 0 )
	{
		RECT screen_rect{};
		GetWindowRect( GetDesktopWindow( ), &screen_rect );
		screen_res = ImVec2( float( screen_rect.right ), float( screen_rect.bottom ) );
		window_pos = ( screen_res - window_size ) * 0.5f;

		// init images here
	}
}