#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>

#include <linuxpe>

#include "../helpers/structs.h"
#include "../file/file.h"

#include "../logger/logger.h"

#include "../json/json.h"


namespace fusion::pe
{
	template <bool x64 = true>
	class c_image
	{
	private:
		win::image_t<x64>* m_image; // our image to premapp
		std::vector<char> m_buffer; // our image buffer
		std::string m_name; // our binary path

		std::unordered_map<std::string, std::vector<import_t>> m_imports; // binary imports name
		std::vector<section_t> m_sections; // our binary sections
		std::vector<std::pair<uint32_t, win::reloc_entry_t>> m_relocs; // our binary relocs

	public:
		c_image( ) = default;

		c_image( const std::string name ) : m_image( nullptr ), m_name( name )
		{
			fusion::logger::info( "initializing \"{}\" binary", name );

			if ( !fusion::file::read_file( name, m_buffer ) )
			{
				fusion::logger::error( "failed to load binary on path: \"{}\"", name );
				return;
			}

			m_image = reinterpret_cast< win::image_t<x64>* >( m_buffer.data( ) );

			load_binary( );
			fusion::logger::info( "\"{}\" success inited", name );
		}

		bool initialize( const char* file_path )
		{
			fusion::logger::info( "initializing \"{}\" binary", file_path );

			m_name = file_path;

			if ( !fusion::file::read_file( file_path, m_buffer ) )
			{
				fusion::logger::error( "failed to load binary on path: \"{}\"", file_path );
				return false;
			}

			m_image = reinterpret_cast< win::image_t<x64>* >( m_buffer.data( ) );

			this->load_binary( );
			fusion::logger::info( "\"{}\" success inited", file_path );

			return true;
		}

		void shutdown( )
		{
			m_image = nullptr;
			m_name = "";
		}

		_declspec( noinline ) void load_binary( )
		{
			parse_sections( );
			parse_relocs( );
			parse_imports( );
		}

		void reload_binary( )
		{
			file::read_file( m_name, m_buffer );

			if ( m_buffer.empty( ) )
			{
				fusion::logger::error( "failed to reload binary on path: \"{}\"", m_name );
				return;
			}

			m_image = reinterpret_cast< win::image_t<x64>* >( m_buffer.data( ) );
			load_binary( );

			fusion::logger::debug( "success reload binaty with path: {}\n", m_name );
		}

	    void parse_sections( )
		{
			const auto nt_header = m_image->get_nt_headers( );
			const size_t n = nt_header->file_header.num_sections;

			for ( auto i = 0; i < n; i++ )
			{
				auto section = nt_header->get_section( i );

				m_sections.emplace_back(
					section_t{
						section->name, section->size_raw_data, section->ptr_raw_data, section->virtual_address
					}
				);
			}

			fusion::logger::debug( "sections success parsed" );

		}

		void parse_relocs( )
		{
			const auto reloc_directory = m_image->get_directory( win::directory_id::directory_entry_basereloc );

			if ( !reloc_directory ) return;

			const auto ptr = m_image->rva_to_ptr( reloc_directory->rva );
			auto block = reinterpret_cast< win::reloc_block_t* >( ptr );

			while ( block->base_rva )
			{
				for ( auto i = 0; i < block->num_entries( ); ++i )
				{
					auto entry = block->entries[ i ];

					m_relocs.emplace_back( std::make_pair( block->base_rva, entry ) );
				}

				block = block->get_next( );
			}

			fusion::logger::debug( "relocs success parsed" );

		}

		void parse_imports( )
		{
			const auto import_directory = m_image->get_directory( win::directory_id::directory_entry_import );
			if ( !import_directory ) return;

			const auto ptr = m_image->rva_to_ptr( import_directory->rva );
			auto table = reinterpret_cast< win::import_directory_t* >( ptr );

			for ( auto previous_name = 0; previous_name < table->rva_name; previous_name = table->rva_name, table++ )
			{
				auto name_ptr = m_image->rva_to_ptr( table->rva_name );
				auto mod_name = std::string( reinterpret_cast< char* >( name_ptr ) );

				auto thunk = reinterpret_cast< win::image_thunk_data_t<x64>* >( m_image->rva_to_ptr( table->rva_original_first_thunk ) );

				auto step = x64 ? sizeof( uint64_t ) : sizeof( uint32_t );
				for ( auto index = 0; thunk->address; index += step, thunk++ )
				{
					auto named_import = reinterpret_cast< win::image_named_import_t* >( m_image->rva_to_ptr( thunk->address ) );

					if ( thunk->is_ordinal )
					{
						fusion::logger::error( "Found ordinal import in module: \"{}\", \"{}\"", mod_name, m_name );
						
						continue;
					}

					import_t data{};
					data.name = reinterpret_cast< const char* >( named_import->name );
					data.rva = table->rva_first_thunk + index;
					std::transform( mod_name.begin( ), mod_name.end( ), mod_name.begin( ), ::tolower );

					fusion::logger::debug( "parsed name: \"{}\" module \"{}\"", named_import->name, mod_name );

					m_imports[ mod_name ].emplace_back( std::move( data ) );
				}

			}
			fusion::logger::debug( "imports success parsed" );

		}

		void get_binary( std::vector<char>& out )
		{
			const auto nt = m_image->get_nt_headers( );
			const auto n = nt->file_header.num_sections;

			out.resize( nt->optional_header.size_image );

			for ( auto& sec : m_sections )
			{
				if ( sec.name == ".reloc" || sec.name == ".rsrc" || sec.name == ".idata" )
				{
					continue;
				}

				memcpy( &out[ sec.va ], &m_buffer[ sec.rva ], sec.size );
			}

			fusion::logger::warn( "sections success copied" );

		}

		void relocate( std::vector<char>& image, uintptr_t base )
		{
			const auto delta = base - m_image->get_nt_headers( )->optional_header.image_base;

			if ( delta > 0 )
			{
				for ( auto& [base_rva, entry] : m_relocs )
				{
					if ( x64 )
					{
						if ( entry.type == win::rel_based_high_low || entry.type == win::rel_based_dir64 )
						{
							*reinterpret_cast< uint64_t* >( image.data( ) + base_rva + entry.offset ) += delta;
						}
						continue;
					}
					
					if ( entry.type == win::rel_based_high_low )
					{
						*reinterpret_cast< uint32_t* >( image.data( ) + base_rva + entry.offset ) += delta;
					}
				}
			}

			fusion::logger::warn( "image success relocated" );

		}

		void fix_imports( std::vector<char>& image, const std::string imports )
		{
			if ( !nlohmann::json::accept( imports.data( ) ) )
			{
				fusion::logger::error( "imports aren\'t valid json" );
				return;
			}

			auto j = nlohmann::json::parse( imports.data( ) );
			for ( auto& [mod, funcs] : m_imports )
			{
				for ( auto& func : funcs )
				{
					if ( !j.contains( func.name ) )
					{
						fusion::logger::error( "missing \"{}\" import address", func.name );
						continue;
					}

					auto addr = j[ func.name ];

					if ( x64 )
					{
						*reinterpret_cast< uint64_t* >( image.data( ) + func.rva ) = addr;
						continue;
					}

					*reinterpret_cast< uint32_t* >( image.data( ) + func.rva ) = addr;
				}
			}
		}

		operator bool( ) const
		{
			return m_image != nullptr;
		}

		auto& imports( ) const
		{
			return m_imports;
		}

		auto& relocs( ) const
		{
			return m_relocs;
		}

		auto& sections( ) const
		{
			return m_sections;
		}

		auto& image( ) const
		{
			return m_image;
		}

		std::string get_imports( )
		{
			nlohmann::json j;

			for ( auto& [mod, imports] : m_imports )
			{
				for ( auto& i : imports )
				{
					j[ mod ].emplace_back( i.name );
				}
			}
			return j.dump( );
		}
	};

}