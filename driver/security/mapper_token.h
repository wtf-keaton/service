#pragma once

namespace fusion::security
{
	TIME_FIELDS get_current_time( )
	{
		LARGE_INTEGER system_time{};
		KeQuerySystemTime( &system_time );

		LARGE_INTEGER local_time{};
		ExSystemTimeToLocalTime( &system_time, &local_time );

		TIME_FIELDS time_fields{};
		RtlTimeToTimeFields( &local_time, &time_fields );

		return time_fields;
	}

	uint64_t generate_mapper_token( )
	{
		auto current_date = get_current_time( );

		auto sum = current_date.Hour + current_date.Minute + current_date.Month + current_date.Year;
		auto xored_sum = _byteswap_uint64( _rotl64( _rotr64( sum ^ 0x2547f, 8 ) ^ 0x7f5ea2f, 7 ) ^ 0x7dffff8e5c1abff4 );

		return xored_sum;
	}
}