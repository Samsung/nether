/*
 *  Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Jan Olszak <j.olszak@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */

/**
 * @file
 * @author  Jan Olszak (j.olszak@samsung.com)
 * @brief   Functions to handle LogLevel
 */

#include "logger/config.hpp"
#include "logger/level.hpp"

#include <stdexcept>
#if defined(HAVE_BOOST)
#include <boost/algorithm/string.hpp>

namespace logger
{

	LogLevel parseLogLevel(const std::string& level)
	{
		if(boost::iequals(level, "ERROR"))
		{
			return LogLevel::ERROR;
		}
		else
			if(boost::iequals(level, "WARN"))
			{
				return LogLevel::WARN;
			}
			else
				if(boost::iequals(level, "INFO"))
				{
					return LogLevel::INFO;
				}
				else
					if(boost::iequals(level, "DEBUG"))
					{
						return LogLevel::DEBUG;
					}
					else
						if(boost::iequals(level, "TRACE"))
						{
							return LogLevel::TRACE;
						}
						else
							if(boost::iequals(level, "HELP"))
							{
								return LogLevel::HELP;
							}
							else
							{
								throw std::runtime_error("Invalid LogLevel to parse");
							}
	}
#else
#include <string.h>
namespace logger
{

	LogLevel parseLogLevel(const std::string& level)
	{
		if(strcmp(level.c_str(), "ERROR"))
		{
			return LogLevel::ERROR;
		}
		else
			if(strcmp(level.c_str(), "WARN") == 0)
			{
				return LogLevel::WARN;
			}
			else
				if(strcmp(level.c_str(), "INFO") == 0)
				{
					return LogLevel::INFO;
				}
				else
					if(strcmp(level.c_str(), "DEBUG") == 0)
					{
						return LogLevel::DEBUG;
					}
					else
						if(strcmp(level.c_str(), "TRACE") == 0)
						{
							return LogLevel::TRACE;
						}
						else
							if(strcmp(level.c_str(), "HELP") == 0)
							{
								return LogLevel::HELP;
							}
							else
							{
								throw std::runtime_error("Invalid LogLevel to parse");
							}
	}
#endif

	std::string toString(const LogLevel logLevel)
	{
		switch(logLevel)
		{
			case LogLevel::ERROR:
				return "ERROR";
			case LogLevel::WARN:
				return "WARN";
			case LogLevel::INFO:
				return "INFO";
			case LogLevel::DEBUG:
				return "DEBUG";
			case LogLevel::TRACE:
				return "TRACE";
			case LogLevel::HELP:
				return "HELP";
			default:
				return "UNKNOWN";
		}
	}
} // namespace logger

