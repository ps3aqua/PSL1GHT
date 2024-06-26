/*
   Copyright (C) 2006, 2007 Sony Computer Entertainment Inc.
   All rights reserved.

   Redistribution and use in source and binary forms,
   with or without modification, are permitted provided that the
   following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the Sony Computer Entertainment Inc nor the names
      of its contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _VECTORMATH_AOS_CPP_PPU_H
#define _VECTORMATH_AOS_CPP_PPU_H

#include <math.h>
#include <altivec.h>
#include "vecidx_aos.h"
#include "floatInVec.h"
#include "boolInVec.h"

#ifdef _VECTORMATH_DEBUG
#include <stdio.h>
#endif

namespace Vectormath {

namespace Aos {

//-----------------------------------------------------------------------------
// Forward Declarations
//

class Vector3;
class Vector4;
class Point3;
class Quat;
class Matrix3;
class Matrix4;
class Transform3;

// A 3-D vector in array-of-structures format
//
class Vector3
{
    vec_float4 mVec128;

public:
    // Default constructor; does no initialization
    // 
    inline Vector3( ) : mVec128((vec_float4){0.0f, 0.0f, 0.0f, 0.0f}) { };

    // Construct a 3-D vector from x, y, and z elements
    // 
    inline Vector3( float x, float y, float z );

    // Construct a 3-D vector from x, y, and z elements (scalar data contained in vector data type)
    // 
    inline Vector3( floatInVec x, floatInVec y, floatInVec z );

    // Copy elements from a 3-D point into a 3-D vector
    // 
    explicit inline Vector3( Point3 pnt );

    // Set all elements of a 3-D vector to the same scalar value
    // 
    explicit inline Vector3( float scalar );

    // Set all elements of a 3-D vector to the same scalar value (scalar data contained in vector data type)
    // 
    explicit inline Vector3( floatInVec scalar );

    // Set vector float data in a 3-D vector
    // 
    explicit inline Vector3( vec_float4 vf4 );

    // Get vector float data from a 3-D vector
    // 
    inline vec_float4 get128( ) const;

    // Assign one 3-D vector to another
    // 
    inline Vector3 & operator =( Vector3 vec );

    // Set the x element of a 3-D vector
    // 
    inline Vector3 & setX( float x );

    // Set the y element of a 3-D vector
    // 
    inline Vector3 & setY( float y );

    // Set the z element of a 3-D vector
    // 
    inline Vector3 & setZ( float z );

    // Set the x element of a 3-D vector (scalar data contained in vector data type)
    // 
    inline Vector3 & setX( floatInVec x );

    // Set the y element of a 3-D vector (scalar data contained in vector data type)
    // 
    inline Vector3 & setY( floatInVec y );

    // Set the z element of a 3-D vector (scalar data contained in vector data type)
    // 
    inline Vector3 & setZ( floatInVec z );

    // Get the x element of a 3-D vector
    // 
    inline const floatInVec getX( ) const;

    // Get the y element of a 3-D vector
    // 
    inline const floatInVec getY( ) const;

    // Get the z element of a 3-D vector
    // 
    inline const floatInVec getZ( ) const;

    // Set an x, y, or z element of a 3-D vector by index
    // 
    inline Vector3 & setElem( int idx, float value );

    // Set an x, y, or z element of a 3-D vector by index (scalar data contained in vector data type)
    // 
    inline Vector3 & setElem( int idx, floatInVec value );

    // Get an x, y, or z element of a 3-D vector by index
    // 
    inline const floatInVec getElem( int idx ) const;

    // Subscripting operator to set or get an element
    // 
    inline VecIdx operator []( int idx );

    // Subscripting operator to get an element
    // 
    inline const floatInVec operator []( int idx ) const;

    // Add two 3-D vectors
    // 
    inline const Vector3 operator +( Vector3 vec ) const;

    // Subtract a 3-D vector from another 3-D vector
    // 
    inline const Vector3 operator -( Vector3 vec ) const;

    // Add a 3-D vector to a 3-D point
    // 
    inline const Point3 operator +( Point3 pnt ) const;

    // Multiply a 3-D vector by a scalar
    // 
    inline const Vector3 operator *( float scalar ) const;

    // Divide a 3-D vector by a scalar
    // 
    inline const Vector3 operator /( float scalar ) const;

    // Multiply a 3-D vector by a scalar (scalar data contained in vector data type)
    // 
    inline const Vector3 operator *( floatInVec scalar ) const;

    // Divide a 3-D vector by a scalar (scalar data contained in vector data type)
    // 
    inline const Vector3 operator /( floatInVec scalar ) const;

    // Multiply a 3-D vector by a 3-D vector
    // 
    inline const Vector3 operator *( Vector3 vec ) const;

    // Divide a 3-D vector by a 3-D vector
    // 
    inline const Vector3 operator /( Vector3 vec ) const;

    // Perform compound assignment and addition with a 3-D vector
    // 
    inline Vector3 & operator +=( Vector3 vec );

    // Perform compound assignment and subtraction by a 3-D vector
    // 
    inline Vector3 & operator -=( Vector3 vec );

    // Perform compound assignment and multiplication by a scalar
    // 
    inline Vector3 & operator *=( float scalar );

    // Perform compound assignment and division by a scalar
    // 
    inline Vector3 & operator /=( float scalar );

    // Perform compound assignment and multiplication by a scalar (scalar data contained in vector data type)
    // 
    inline Vector3 & operator *=( floatInVec scalar );

    // Perform compound assignment and division by a scalar (scalar data contained in vector data type)
    // 
    inline Vector3 & operator /=( floatInVec scalar );

    // Perform compound assignment and multiplication by a 3-D vector
    // 
    inline Vector3 & operator *=( Vector3 vec );

    // Perform compound assignment and division by a 3-D vector
    // 
    inline Vector3 & operator /=( Vector3 vec );

    // Negate all elements of a 3-D vector
    // 
    inline const Vector3 operator -( ) const;

	// Perform equality comparsion of two 3-D vector
	//
	inline bool operator == (const Vector3& vec) const;
	
	// Perform equality comparsion of two 3-D vector
	//
	inline bool operator != (const Vector3& vec) const;
	
    // Construct x axis
    // 
    static inline const Vector3 xAxis( );

    // Construct y axis
    // 
    static inline const Vector3 yAxis( );

    // Construct z axis
    // 
    static inline const Vector3 zAxis( );
    
};

// Multiply a 3-D vector by a scalar
// 
inline const Vector3 operator *( float scalar, Vector3 vec );

// Multiply a 3-D vector by a scalar (scalar data contained in vector data type)
// 
inline const Vector3 operator *( floatInVec scalar, Vector3 vec );

// Multiply two 3-D vectors per element
// 
inline const Vector3 mulPerElem( Vector3 vec0, Vector3 vec1 );

// Divide two 3-D vectors per element
// NOTE: 
// Floating-point behavior matches standard library function divf4.
// 
inline const Vector3 divPerElem( Vector3 vec0, Vector3 vec1 );

// Compute the reciprocal of a 3-D vector per element
// NOTE: 
// Floating-point behavior matches standard library function recipf4.
// 
inline const Vector3 recipPerElem( Vector3 vec );

// Compute the square root of a 3-D vector per element
// NOTE: 
// Floating-point behavior matches standard library function sqrtf4.
// 
inline const Vector3 sqrtPerElem( Vector3 vec );

// Compute the reciprocal square root of a 3-D vector per element
// NOTE: 
// Floating-point behavior matches standard library function rsqrtf4.
// 
inline const Vector3 rsqrtPerElem( Vector3 vec );

// Compute the absolute value of a 3-D vector per element
// 
inline const Vector3 absPerElem( Vector3 vec );

// Copy sign from one 3-D vector to another, per element
// 
inline const Vector3 copySignPerElem( Vector3 vec0, Vector3 vec1 );

// Maximum of two 3-D vectors per element
// 
inline const Vector3 maxPerElem( Vector3 vec0, Vector3 vec1 );

// Minimum of two 3-D vectors per element
// 
inline const Vector3 minPerElem( Vector3 vec0, Vector3 vec1 );

// Maximum element of a 3-D vector
// 
inline const floatInVec maxElem( Vector3 vec );

// Minimum element of a 3-D vector
// 
inline const floatInVec minElem( Vector3 vec );

// Compute the sum of all elements of a 3-D vector
// 
inline const floatInVec sum( Vector3 vec );

// Compute the dot product of two 3-D vectors
// 
inline const floatInVec dot( Vector3 vec0, Vector3 vec1 );

// Compute the square of the length of a 3-D vector
// 
inline const floatInVec lengthSqr( Vector3 vec );

// Compute the length of a 3-D vector
// 
inline const floatInVec length( Vector3 vec );

// Normalize a 3-D vector
// NOTE: 
// The result is unpredictable when all elements of vec are at or near zero.
// 
inline const Vector3 normalize( Vector3 vec );

// Compute cross product of two 3-D vectors
// 
inline const Vector3 cross( Vector3 vec0, Vector3 vec1 );

// Outer product of two 3-D vectors
// 
inline const Matrix3 outer( Vector3 vec0, Vector3 vec1 );

// Pre-multiply a row vector by a 3x3 matrix
// NOTE: 
// Slower than column post-multiply.
// 
inline const Vector3 rowMul( Vector3 vec, const Matrix3 & mat );

// Cross-product matrix of a 3-D vector
// 
inline const Matrix3 crossMatrix( Vector3 vec );

// Create cross-product matrix and multiply
// NOTE: 
// Faster than separately creating a cross-product matrix and multiplying.
// 
inline const Matrix3 crossMatrixMul( Vector3 vec, const Matrix3 & mat );

// Linear interpolation between two 3-D vectors
// NOTE: 
// Does not clamp t between 0 and 1.
// 
inline const Vector3 lerp( float t, Vector3 vec0, Vector3 vec1 );

// Linear interpolation between two 3-D vectors (scalar data contained in vector data type)
// NOTE: 
// Does not clamp t between 0 and 1.
// 
inline const Vector3 lerp( floatInVec t, Vector3 vec0, Vector3 vec1 );

// Spherical linear interpolation between two 3-D vectors
// NOTE: 
// The result is unpredictable if the vectors point in opposite directions.
// Does not clamp t between 0 and 1.
// 
inline const Vector3 slerp( float t, Vector3 unitVec0, Vector3 unitVec1 );

// Spherical linear interpolation between two 3-D vectors (scalar data contained in vector data type)
// NOTE: 
// The result is unpredictable if the vectors point in opposite directions.
// Does not clamp t between 0 and 1.
// 
inline const Vector3 slerp( floatInVec t, Vector3 unitVec0, Vector3 unitVec1 );

// Conditionally select between two 3-D vectors
// NOTE: 
// This function uses a conditional select instruction to avoid a branch.
// However, the transfer of select1 to a VMX register may use more processing time than a branch.
// Use the boolInVec version for better performance.
// 
inline const Vector3 select( Vector3 vec0, Vector3 vec1, bool select1 );

// Conditionally select between two 3-D vectors (scalar data contained in vector data type)
// NOTE: 
// This function uses a conditional select instruction to avoid a branch.
// 
inline const Vector3 select( Vector3 vec0, Vector3 vec1, boolInVec select1 );

// Load x, y, and z elements from the first three words of a quadword.
// 
// 
inline void loadXYZ( Vector3 & vec, const vec_float4 * quad );

// Load x, y, and z elements from the first three words of a float array.
// 
// 
inline void loadXYZ( Vector3 & vec, const float * fptr );

// Store x, y, and z elements of a 3-D vector in the first three words of a quadword.
// The value of the fourth word (the word with the highest address) remains unchanged
// 
inline void storeXYZ( Vector3 vec, vec_float4 * quad );

// Store x, y, and z elements of a 3-D vector in the first three words of a float array.
// Memory area of previous 16 bytes and next 32 bytes from fptr might be accessed
// 
inline void storeXYZ( Vector3 vec, float * fptr );

// Load four three-float 3-D vectors, stored in three quadwords
// 
inline void loadXYZArray( Vector3 & vec0, Vector3 & vec1, Vector3 & vec2, Vector3 & vec3, const vec_float4 * threeQuads );

// Store four 3-D vectors in three quadwords
// 
inline void storeXYZArray( Vector3 vec0, Vector3 vec1, Vector3 vec2, Vector3 vec3, vec_float4 * threeQuads );

// Store eight 3-D vectors as half-floats
// 
inline void storeHalfFloats( Vector3 vec0, Vector3 vec1, Vector3 vec2, Vector3 vec3, Vector3 vec4, Vector3 vec5, Vector3 vec6, Vector3 vec7, vec_ushort8 * threeQuads );

#ifdef _VECTORMATH_DEBUG

// Print a 3-D vector
// NOTE: 
// Function is only defined when _VECTORMATH_DEBUG is defined.
// 
inline void print( Vector3 vec );

// Print a 3-D vector and an associated string identifier
// NOTE: 
// Function is only defined when _VECTORMATH_DEBUG is defined.
// 
inline void print( Vector3 vec, const char * name );

#endif

// A 4-D vector in array-of-structures format
//
class Vector4
{
    vec_float4 mVec128;

public:
    // Default constructor; does no initialization
    // 
    inline Vector4( ) : mVec128((vec_float4){0.0f, 0.0f, 0.0f, 0.0f}) { };

    // Construct a 4-D vector from x, y, z, and w elements
    // 
    inline Vector4( float x, float y, float z, float w );

    // Construct a 4-D vector from x, y, z, and w elements (scalar data contained in vector data type)
    // 
    inline Vector4( floatInVec x, floatInVec y, floatInVec z, floatInVec w );

    // Construct a 4-D vector from a 3-D vector and a scalar
    // 
    inline Vector4( Vector3 xyz, float w );

    // Construct a 4-D vector from a 3-D vector and a scalar (scalar data contained in vector data type)
    // 
    inline Vector4( Vector3 xyz, floatInVec w );

    // Copy x, y, and z from a 3-D vector into a 4-D vector, and set w to 0
    // 
    explicit inline Vector4( Vector3 vec );

    // Copy x, y, and z from a 3-D point into a 4-D vector, and set w to 1
    // 
    explicit inline Vector4( Point3 pnt );

    // Copy elements from a quaternion into a 4-D vector
    // 
    explicit inline Vector4( Quat quat );

    // Set all elements of a 4-D vector to the same scalar value
    // 
    explicit inline Vector4( float scalar );

    // Set all elements of a 4-D vector to the same scalar value (scalar data contained in vector data type)
    // 
    explicit inline Vector4( floatInVec scalar );

    // Set vector float data in a 4-D vector
    // 
    explicit inline Vector4( vec_float4 vf4 );

    // Get vector float data from a 4-D vector
    // 
    inline vec_float4 get128( ) const;

    // Assign one 4-D vector to another
    // 
    inline Vector4 & operator =( Vector4 vec );

    // Set the x, y, and z elements of a 4-D vector
    // NOTE: 
    // This function does not change the w element.
    // 
    inline Vector4 & setXYZ( Vector3 vec );

    // Get the x, y, and z elements of a 4-D vector
    // 
    inline const Vector3 getXYZ( ) const;

    // Set the x element of a 4-D vector
    // 
    inline Vector4 & setX( float x );

    // Set the y element of a 4-D vector
    // 
    inline Vector4 & setY( float y );

    // Set the z element of a 4-D vector
    // 
    inline Vector4 & setZ( float z );

    // Set the w element of a 4-D vector
    // 
    inline Vector4 & setW( float w );

    // Set the x element of a 4-D vector (scalar data contained in vector data type)
    // 
    inline Vector4 & setX( floatInVec x );

    // Set the y element of a 4-D vector (scalar data contained in vector data type)
    // 
    inline Vector4 & setY( floatInVec y );

    // Set the z element of a 4-D vector (scalar data contained in vector data type)
    // 
    inline Vector4 & setZ( floatInVec z );

    // Set the w element of a 4-D vector (scalar data contained in vector data type)
    // 
    inline Vector4 & setW( floatInVec w );

    // Get the x element of a 4-D vector
    // 
    inline const floatInVec getX( ) const;

    // Get the y element of a 4-D vector
    // 
    inline const floatInVec getY( ) const;

    // Get the z element of a 4-D vector
    // 
    inline const floatInVec getZ( ) const;

    // Get the w element of a 4-D vector
    // 
    inline const floatInVec getW( ) const;

    // Set an x, y, z, or w element of a 4-D vector by index
    // 
    inline Vector4 & setElem( int idx, float value );

    // Set an x, y, z, or w element of a 4-D vector by index (scalar data contained in vector data type)
    // 
    inline Vector4 & setElem( int idx, floatInVec value );

    // Get an x, y, z, or w element of a 4-D vector by index
    // 
    inline const floatInVec getElem( int idx ) const;

    // Subscripting operator to set or get an element
    // 
    inline VecIdx operator []( int idx );

    // Subscripting operator to get an element
    // 
    inline const floatInVec operator []( int idx ) const;

    // Add two 4-D vectors
    // 
    inline const Vector4 operator +( Vector4 vec ) const;

    // Subtract a 4-D vector from another 4-D vector
    // 
    inline const Vector4 operator -( Vector4 vec ) const;

    // Multiply a 4-D vector by a scalar
    // 
    inline const Vector4 operator *( float scalar ) const;

    // Divide a 4-D vector by a scalar
    // 
    inline const Vector4 operator /( float scalar ) const;

    // Multiply a 4-D vector by a scalar (scalar data contained in vector data type)
    // 
    inline const Vector4 operator *( floatInVec scalar ) const;

    // Divide a 4-D vector by a scalar (scalar data contained in vector data type)
    // 
    inline const Vector4 operator /( floatInVec scalar ) const;

    // Multiply a 4-D vector by a 4-D vector
    // 
    inline const Vector4 operator *( Vector4 vec ) const;

    // Divide a 4-D vector by a 4-D vector
    // 
    inline const Vector4 operator /( Vector4 vec ) const;

    // Perform compound assignment and addition with a 4-D vector
    // 
    inline Vector4 & operator +=( Vector4 vec );

    // Perform compound assignment and subtraction by a 4-D vector
    // 
    inline Vector4 & operator -=( Vector4 vec );

    // Perform compound assignment and multiplication by a scalar
    // 
    inline Vector4 & operator *=( float scalar );

    // Perform compound assignment and division by a scalar
    // 
    inline Vector4 & operator /=( float scalar );

    // Perform compound assignment and multiplication by a scalar (scalar data contained in vector data type)
    // 
    inline Vector4 & operator *=( floatInVec scalar );

    // Perform compound assignment and division by a scalar (scalar data contained in vector data type)
    // 
    inline Vector4 & operator /=( floatInVec scalar );

    // Perform compound assignment and multiplication by a 4-D vector
    // 
    inline Vector4 & operator *=( Vector4 vec );

    // Perform compound assignment and division by a 4-D vector
    // 
    inline Vector4 & operator /=( Vector4 vec );

    // Negate all elements of a 4-D vector
    // 
    inline const Vector4 operator -( ) const;

	// Perform equality comparsion of two 4-D vector
	//
	inline bool operator == (const Vector4& vec) const;
	
	// Perform equality comparsion of two 4-D vector
	//
	inline bool operator != (const Vector4& vec) const;
	
    // Construct x axis
    // 
    static inline const Vector4 xAxis( );

    // Construct y axis
    // 
    static inline const Vector4 yAxis( );

    // Construct z axis
    // 
    static inline const Vector4 zAxis( );

    // Construct w axis
    // 
    static inline const Vector4 wAxis( );

};

// Multiply a 4-D vector by a scalar
// 
inline const Vector4 operator *( float scalar, Vector4 vec );

// Multiply a 4-D vector by a scalar (scalar data contained in vector data type)
// 
inline const Vector4 operator *( floatInVec scalar, Vector4 vec );

// Multiply two 4-D vectors per element
// 
inline const Vector4 mulPerElem( Vector4 vec0, Vector4 vec1 );

// Divide two 4-D vectors per element
// NOTE: 
// Floating-point behavior matches standard library function divf4.
// 
inline const Vector4 divPerElem( Vector4 vec0, Vector4 vec1 );

// Compute the reciprocal of a 4-D vector per element
// NOTE: 
// Floating-point behavior matches standard library function recipf4.
// 
inline const Vector4 recipPerElem( Vector4 vec );

// Compute the square root of a 4-D vector per element
// NOTE: 
// Floating-point behavior matches standard library function sqrtf4.
// 
inline const Vector4 sqrtPerElem( Vector4 vec );

// Compute the reciprocal square root of a 4-D vector per element
// NOTE: 
// Floating-point behavior matches standard library function rsqrtf4.
// 
inline const Vector4 rsqrtPerElem( Vector4 vec );

// Compute the absolute value of a 4-D vector per element
// 
inline const Vector4 absPerElem( Vector4 vec );

// Copy sign from one 4-D vector to another, per element
// 
inline const Vector4 copySignPerElem( Vector4 vec0, Vector4 vec1 );

// Maximum of two 4-D vectors per element
// 
inline const Vector4 maxPerElem( Vector4 vec0, Vector4 vec1 );

// Minimum of two 4-D vectors per element
// 
inline const Vector4 minPerElem( Vector4 vec0, Vector4 vec1 );

// Maximum element of a 4-D vector
// 
inline const floatInVec maxElem( Vector4 vec );

// Minimum element of a 4-D vector
// 
inline const floatInVec minElem( Vector4 vec );

// Compute the sum of all elements of a 4-D vector
// 
inline const floatInVec sum( Vector4 vec );

// Compute the dot product of two 4-D vectors
// 
inline const floatInVec dot( Vector4 vec0, Vector4 vec1 );

// Compute the square of the length of a 4-D vector
// 
inline const floatInVec lengthSqr( Vector4 vec );

// Compute the length of a 4-D vector
// 
inline const floatInVec length( Vector4 vec );

// Normalize a 4-D vector
// NOTE: 
// The result is unpredictable when all elements of vec are at or near zero.
// 
inline const Vector4 normalize( Vector4 vec );

// Outer product of two 4-D vectors
// 
inline const Matrix4 outer( Vector4 vec0, Vector4 vec1 );

// Linear interpolation between two 4-D vectors
// NOTE: 
// Does not clamp t between 0 and 1.
// 
inline const Vector4 lerp( float t, Vector4 vec0, Vector4 vec1 );

// Linear interpolation between two 4-D vectors (scalar data contained in vector data type)
// NOTE: 
// Does not clamp t between 0 and 1.
// 
inline const Vector4 lerp( floatInVec t, Vector4 vec0, Vector4 vec1 );

// Spherical linear interpolation between two 4-D vectors
// NOTE: 
// The result is unpredictable if the vectors point in opposite directions.
// Does not clamp t between 0 and 1.
// 
inline const Vector4 slerp( float t, Vector4 unitVec0, Vector4 unitVec1 );

// Spherical linear interpolation between two 4-D vectors (scalar data contained in vector data type)
// NOTE: 
// The result is unpredictable if the vectors point in opposite directions.
// Does not clamp t between 0 and 1.
// 
inline const Vector4 slerp( floatInVec t, Vector4 unitVec0, Vector4 unitVec1 );

// Conditionally select between two 4-D vectors
// NOTE: 
// This function uses a conditional select instruction to avoid a branch.
// However, the transfer of select1 to a VMX register may use more processing time than a branch.
// Use the boolInVec version for better performance.
// 
inline const Vector4 select( Vector4 vec0, Vector4 vec1, bool select1 );

// Conditionally select between two 4-D vectors (scalar data contained in vector data type)
// NOTE: 
// This function uses a conditional select instruction to avoid a branch.
// 
inline const Vector4 select( Vector4 vec0, Vector4 vec1, boolInVec select1 );

// Store four 4-D vectors as half-floats
// 
inline void storeHalfFloats( Vector4 vec0, Vector4 vec1, Vector4 vec2, Vector4 vec3, vec_ushort8 * twoQuads );

// Load x, y, z, and w elements from the first four words of a float array.
// 
// 
inline void loadXYZW( Vector4 & vec, const float * fptr );

// Store x, y, z, and w elements of a 4-D vector in the first four words of a float array.
// Memory area of previous 16 bytes and next 32 bytes from fptr might be accessed
// 
inline void storeXYZW( Vector4 vec, float * fptr );

#ifdef _VECTORMATH_DEBUG

// Print a 4-D vector
// NOTE: 
// Function is only defined when _VECTORMATH_DEBUG is defined.
// 
inline void print( Vector4 vec );

// Print a 4-D vector and an associated string identifier
// NOTE: 
// Function is only defined when _VECTORMATH_DEBUG is defined.
// 
inline void print( Vector4 vec, const char * name );

#endif

// A 3-D point in array-of-structures format
//
class Point3
{
    vec_float4 mVec128;

public:
    // Default constructor; does no initialization
    // 
    inline Point3( ) : mVec128((vec_float4){0.0f, 0.0f, 0.0f, 0.0f}) { };

    // Construct a 3-D point from x, y, and z elements
    // 
    inline Point3( float x, float y, float z );

    // Construct a 3-D point from x, y, and z elements (scalar data contained in vector data type)
    // 
    inline Point3( floatInVec x, floatInVec y, floatInVec z );

    // Copy elements from a 3-D vector into a 3-D point
    // 
    explicit inline Point3( Vector3 vec );

    // Set all elements of a 3-D point to the same scalar value
    // 
    explicit inline Point3( float scalar );

    // Set all elements of a 3-D point to the same scalar value (scalar data contained in vector data type)
    // 
    explicit inline Point3( floatInVec scalar );

    // Set vector float data in a 3-D point
    // 
    explicit inline Point3( vec_float4 vf4 );

    // Get vector float data from a 3-D point
    // 
    inline vec_float4 get128( ) const;

    // Assign one 3-D point to another
    // 
    inline Point3 & operator =( Point3 pnt );

    // Set the x element of a 3-D point
    // 
    inline Point3 & setX( float x );

    // Set the y element of a 3-D point
    // 
    inline Point3 & setY( float y );

    // Set the z element of a 3-D point
    // 
    inline Point3 & setZ( float z );

    // Set the x element of a 3-D point (scalar data contained in vector data type)
    // 
    inline Point3 & setX( floatInVec x );

    // Set the y element of a 3-D point (scalar data contained in vector data type)
    // 
    inline Point3 & setY( floatInVec y );

    // Set the z element of a 3-D point (scalar data contained in vector data type)
    // 
    inline Point3 & setZ( floatInVec z );

    // Get the x element of a 3-D point
    // 
    inline const floatInVec getX( ) const;

    // Get the y element of a 3-D point
    // 
    inline const floatInVec getY( ) const;

    // Get the z element of a 3-D point
    // 
    inline const floatInVec getZ( ) const;

    // Set an x, y, or z element of a 3-D point by index
    // 
    inline Point3 & setElem( int idx, float value );

    // Set an x, y, or z element of a 3-D point by index (scalar data contained in vector data type)
    // 
    inline Point3 & setElem( int idx, floatInVec value );

    // Get an x, y, or z element of a 3-D point by index
    // 
    inline const floatInVec getElem( int idx ) const;

    // Subscripting operator to set or get an element
    // 
    inline VecIdx operator []( int idx );

    // Subscripting operator to get an element
    // 
    inline const floatInVec operator []( int idx ) const;

    // Subtract a 3-D point from another 3-D point
    // 
    inline const Vector3 operator -( Point3 pnt ) const;

    // Add a 3-D point to a 3-D vector
    // 
    inline const Point3 operator +( Vector3 vec ) const;

    // Subtract a 3-D vector from a 3-D point
    // 
    inline const Point3 operator -( Vector3 vec ) const;

    // Perform compound assignment and addition with a 3-D vector
    // 
    inline Point3 & operator +=( Vector3 vec );

    // Perform compound assignment and subtraction by a 3-D vector
    // 
    inline Point3 & operator -=( Vector3 vec );

	// Perform equality comparsion of two 3-D point
	//
	inline bool operator == (const Point3& vec) const;
	
	// Perform equality comparsion of two 3-D point
	//
	inline bool operator != (const Point3& vec) const;
};

// Multiply two 3-D points per element
// 
inline const Point3 mulPerElem( Point3 pnt0, Point3 pnt1 );

// Divide two 3-D points per element
// NOTE: 
// Floating-point behavior matches standard library function divf4.
// 
inline const Point3 divPerElem( Point3 pnt0, Point3 pnt1 );

// Compute the reciprocal of a 3-D point per element
// NOTE: 
// Floating-point behavior matches standard library function recipf4.
// 
inline const Point3 recipPerElem( Point3 pnt );

// Compute the square root of a 3-D point per element
// NOTE: 
// Floating-point behavior matches standard library function sqrtf4.
// 
inline const Point3 sqrtPerElem( Point3 pnt );

// Compute the reciprocal square root of a 3-D point per element
// NOTE: 
// Floating-point behavior matches standard library function rsqrtf4.
// 
inline const Point3 rsqrtPerElem( Point3 pnt );

// Compute the absolute value of a 3-D point per element
// 
inline const Point3 absPerElem( Point3 pnt );

// Copy sign from one 3-D point to another, per element
// 
inline const Point3 copySignPerElem( Point3 pnt0, Point3 pnt1 );

// Maximum of two 3-D points per element
// 
inline const Point3 maxPerElem( Point3 pnt0, Point3 pnt1 );

// Minimum of two 3-D points per element
// 
inline const Point3 minPerElem( Point3 pnt0, Point3 pnt1 );

// Maximum element of a 3-D point
// 
inline const floatInVec maxElem( Point3 pnt );

// Minimum element of a 3-D point
// 
inline const floatInVec minElem( Point3 pnt );

// Compute the sum of all elements of a 3-D point
// 
inline const floatInVec sum( Point3 pnt );

// Apply uniform scale to a 3-D point
// 
inline const Point3 scale( Point3 pnt, float scaleVal );

// Apply uniform scale to a 3-D point (scalar data contained in vector data type)
// 
inline const Point3 scale( Point3 pnt, floatInVec scaleVal );

// Apply non-uniform scale to a 3-D point
// 
inline const Point3 scale( Point3 pnt, Vector3 scaleVec );

// Scalar projection of a 3-D point on a unit-length 3-D vector
// 
inline const floatInVec projection( Point3 pnt, Vector3 unitVec );

// Compute the square of the distance of a 3-D point from the coordinate-system origin
// 
inline const floatInVec distSqrFromOrigin( Point3 pnt );

// Compute the distance of a 3-D point from the coordinate-system origin
// 
inline const floatInVec distFromOrigin( Point3 pnt );

// Compute the square of the distance between two 3-D points
// 
inline const floatInVec distSqr( Point3 pnt0, Point3 pnt1 );

// Compute the distance between two 3-D points
// 
inline const floatInVec dist( Point3 pnt0, Point3 pnt1 );

// Linear interpolation between two 3-D points
// NOTE: 
// Does not clamp t between 0 and 1.
// 
inline const Point3 lerp( float t, Point3 pnt0, Point3 pnt1 );

// Linear interpolation between two 3-D points (scalar data contained in vector data type)
// NOTE: 
// Does not clamp t between 0 and 1.
// 
inline const Point3 lerp( floatInVec t, Point3 pnt0, Point3 pnt1 );

// Conditionally select between two 3-D points
// NOTE: 
// This function uses a conditional select instruction to avoid a branch.
// However, the transfer of select1 to a VMX register may use more processing time than a branch.
// Use the boolInVec version for better performance.
// 
inline const Point3 select( Point3 pnt0, Point3 pnt1, bool select1 );

// Conditionally select between two 3-D points (scalar data contained in vector data type)
// NOTE: 
// This function uses a conditional select instruction to avoid a branch.
// 
inline const Point3 select( Point3 pnt0, Point3 pnt1, boolInVec select1 );

// Load x, y, and z elements from the first three words of a quadword.
// 
// 
inline void loadXYZ( Point3 & pnt, const vec_float4 * quad );

// Load x, y, and z elements from the first three words of a float array.
// 
// 
inline void loadXYZ( Point3 & pnt, const float * fptr );

// Store x, y, and z elements of a 3-D point in the first three words of a quadword.
// The value of the fourth word (the word with the highest address) remains unchanged
// 
inline void storeXYZ( Point3 pnt, vec_float4 * quad );

// Store x, y, and z elements of a 3-D point in the first three words of a float array.
// Memory area of previous 16 bytes and next 32 bytes from fptr might be accessed
// 
inline void storeXYZ( Point3 pnt, float * fptr );

// Load four three-float 3-D points, stored in three quadwords
// 
inline void loadXYZArray( Point3 & pnt0, Point3 & pnt1, Point3 & pnt2, Point3 & pnt3, const vec_float4 * threeQuads );

// Store four 3-D points in three quadwords
// 
inline void storeXYZArray( Point3 pnt0, Point3 pnt1, Point3 pnt2, Point3 pnt3, vec_float4 * threeQuads );

// Store eight 3-D points as half-floats
// 
inline void storeHalfFloats( Point3 pnt0, Point3 pnt1, Point3 pnt2, Point3 pnt3, Point3 pnt4, Point3 pnt5, Point3 pnt6, Point3 pnt7, vec_ushort8 * threeQuads );

#ifdef _VECTORMATH_DEBUG

// Print a 3-D point
// NOTE: 
// Function is only defined when _VECTORMATH_DEBUG is defined.
// 
inline void print( Point3 pnt );

// Print a 3-D point and an associated string identifier
// NOTE: 
// Function is only defined when _VECTORMATH_DEBUG is defined.
// 
inline void print( Point3 pnt, const char * name );

#endif

// A quaternion in array-of-structures format
//
class Quat
{
    vec_float4 mVec128;

public:
    // Default constructor; does no initialization
    // 
    inline Quat( ) : mVec128((vec_float4){0.0f, 0.0f, 0.0f, 0.0f}) { };

    // Construct a quaternion from x, y, z, and w elements
    // 
    inline Quat( float x, float y, float z, float w );

    // Construct a quaternion from x, y, z, and w elements (scalar data contained in vector data type)
    // 
    inline Quat( floatInVec x, floatInVec y, floatInVec z, floatInVec w );

    // Construct a quaternion from a 3-D vector and a scalar
    // 
    inline Quat( Vector3 xyz, float w );

    // Construct a quaternion from a 3-D vector and a scalar (scalar data contained in vector data type)
    // 
    inline Quat( Vector3 xyz, floatInVec w );

    // Copy elements from a 4-D vector into a quaternion
    // 
    explicit inline Quat( Vector4 vec );

    // Convert a rotation matrix to a unit-length quaternion
    // 
    explicit inline Quat( const Matrix3 & rotMat );

    // Set all elements of a quaternion to the same scalar value
    // 
    explicit inline Quat( float scalar );

    // Set all elements of a quaternion to the same scalar value (scalar data contained in vector data type)
    // 
    explicit inline Quat( floatInVec scalar );

    // Set vector float data in a quaternion
    // 
    explicit inline Quat( vec_float4 vf4 );

    // Get vector float data from a quaternion
    // 
    inline vec_float4 get128( ) const;

    // Assign one quaternion to another
    // 
    inline Quat & operator =( Quat quat );

    // Set the x, y, and z elements of a quaternion
    // NOTE: 
    // This function does not change the w element.
    // 
    inline Quat & setXYZ( Vector3 vec );

    // Get the x, y, and z elements of a quaternion
    // 
    inline const Vector3 getXYZ( ) const;

    // Set the x element of a quaternion
    // 
    inline Quat & setX( float x );

    // Set the y element of a quaternion
    // 
    inline Quat & setY( float y );

    // Set the z element of a quaternion
    // 
    inline Quat & setZ( float z );

    // Set the w element of a quaternion
    // 
    inline Quat & setW( float w );

    // Set the x element of a quaternion (scalar data contained in vector data type)
    // 
    inline Quat & setX( floatInVec x );

    // Set the y element of a quaternion (scalar data contained in vector data type)
    // 
    inline Quat & setY( floatInVec y );

    // Set the z element of a quaternion (scalar data contained in vector data type)
    // 
    inline Quat & setZ( floatInVec z );

    // Set the w element of a quaternion (scalar data contained in vector data type)
    // 
    inline Quat & setW( floatInVec w );

    // Get the x element of a quaternion
    // 
    inline const floatInVec getX( ) const;

    // Get the y element of a quaternion
    // 
    inline const floatInVec getY( ) const;

    // Get the z element of a quaternion
    // 
    inline const floatInVec getZ( ) const;

    // Get the w element of a quaternion
    // 
    inline const floatInVec getW( ) const;

    // Set an x, y, z, or w element of a quaternion by index
    // 
    inline Quat & setElem( int idx, float value );

    // Set an x, y, z, or w element of a quaternion by index (scalar data contained in vector data type)
    // 
    inline Quat & setElem( int idx, floatInVec value );

    // Get an x, y, z, or w element of a quaternion by index
    // 
    inline const floatInVec getElem( int idx ) const;

    // Subscripting operator to set or get an element
    // 
    inline VecIdx operator []( int idx );

    // Subscripting operator to get an element
    // 
    inline const floatInVec operator []( int idx ) const;

    // Add two quaternions
    // 
    inline const Quat operator +( Quat quat ) const;

    // Subtract a quaternion from another quaternion
    // 
    inline const Quat operator -( Quat quat ) const;

    // Multiply two quaternions
    // 
    inline const Quat operator *( Quat quat ) const;

    // Multiply a quaternion by a scalar
    // 
    inline const Quat operator *( float scalar ) const;

    // Divide a quaternion by a scalar
    // 
    inline const Quat operator /( float scalar ) const;

    // Multiply a quaternion by a scalar (scalar data contained in vector data type)
    // 
    inline const Quat operator *( floatInVec scalar ) const;

    // Divide a quaternion by a scalar (scalar data contained in vector data type)
    // 
    inline const Quat operator /( floatInVec scalar ) const;

    // Perform compound assignment and addition with a quaternion
    // 
    inline Quat & operator +=( Quat quat );

    // Perform compound assignment and subtraction by a quaternion
    // 
    inline Quat & operator -=( Quat quat );

    // Perform compound assignment and multiplication by a quaternion
    // 
    inline Quat & operator *=( Quat quat );

    // Perform compound assignment and multiplication by a scalar
    // 
    inline Quat & operator *=( float scalar );

    // Perform compound assignment and division by a scalar
    // 
    inline Quat & operator /=( float scalar );

    // Perform compound assignment and multiplication by a scalar (scalar data contained in vector data type)
    // 
    inline Quat & operator *=( floatInVec scalar );

    // Perform compound assignment and division by a scalar (scalar data contained in vector data type)
    // 
    inline Quat & operator /=( floatInVec scalar );

    // Negate all elements of a quaternion
    // 
    inline const Quat operator -( ) const;

    // Construct an identity quaternion
    // 
    static inline const Quat identity( );

    // Construct a quaternion to rotate between two unit-length 3-D vectors
    // NOTE: 
    // The result is unpredictable if unitVec0 and unitVec1 point in opposite directions.
    // 
    static inline const Quat rotation( Vector3 unitVec0, Vector3 unitVec1 );

    // Construct a quaternion to rotate around a unit-length 3-D vector
    // 
    static inline const Quat rotation( float radians, Vector3 unitVec );

    // Construct a quaternion to rotate around a unit-length 3-D vector (scalar data contained in vector data type)
    // 
    static inline const Quat rotation( floatInVec radians, Vector3 unitVec );

    // Construct a quaternion to rotate around the x axis
    // 
    static inline const Quat rotationX( float radians );

    // Construct a quaternion to rotate around the y axis
    // 
    static inline const Quat rotationY( float radians );

    // Construct a quaternion to rotate around the z axis
    // 
    static inline const Quat rotationZ( float radians );

    // Construct a quaternion to rotate around the x axis (scalar data contained in vector data type)
    // 
    static inline const Quat rotationX( floatInVec radians );

    // Construct a quaternion to rotate around the y axis (scalar data contained in vector data type)
    // 
    static inline const Quat rotationY( floatInVec radians );

    // Construct a quaternion to rotate around the z axis (scalar data contained in vector data type)
    // 
    static inline const Quat rotationZ( floatInVec radians );

};

// Multiply a quaternion by a scalar
// 
inline const Quat operator *( float scalar, Quat quat );

// Multiply a quaternion by a scalar (scalar data contained in vector data type)
// 
inline const Quat operator *( floatInVec scalar, Quat quat );

// Compute the conjugate of a quaternion
// 
inline const Quat conj( Quat quat );

// Use a unit-length quaternion to rotate a 3-D vector
// 
inline const Vector3 rotate( Quat unitQuat, Vector3 vec );

// Compute the dot product of two quaternions
// 
inline const floatInVec dot( Quat quat0, Quat quat1 );

// Compute the norm of a quaternion
// 
inline const floatInVec norm( Quat quat );

// Compute the length of a quaternion
// 
inline const floatInVec length( Quat quat );

// Normalize a quaternion
// NOTE: 
// The result is unpredictable when all elements of quat are at or near zero.
// 
inline const Quat normalize( Quat quat );

// Linear interpolation between two quaternions
// NOTE: 
// Does not clamp t between 0 and 1.
// 
inline const Quat lerp( float t, Quat quat0, Quat quat1 );

// Linear interpolation between two quaternions (scalar data contained in vector data type)
// NOTE: 
// Does not clamp t between 0 and 1.
// 
inline const Quat lerp( floatInVec t, Quat quat0, Quat quat1 );

// Spherical linear interpolation between two quaternions
// NOTE: 
// Interpolates along the shortest path between orientations.
// Does not clamp t between 0 and 1.
// 
inline const Quat slerp( float t, Quat unitQuat0, Quat unitQuat1 );

// Spherical linear interpolation between two quaternions (scalar data contained in vector data type)
// NOTE: 
// Interpolates along the shortest path between orientations.
// Does not clamp t between 0 and 1.
// 
inline const Quat slerp( floatInVec t, Quat unitQuat0, Quat unitQuat1 );

// Spherical quadrangle interpolation
// 
inline const Quat squad( float t, Quat unitQuat0, Quat unitQuat1, Quat unitQuat2, Quat unitQuat3 );

// Spherical quadrangle interpolation (scalar data contained in vector data type)
// 
inline const Quat squad( floatInVec t, Quat unitQuat0, Quat unitQuat1, Quat unitQuat2, Quat unitQuat3 );

// Load x, y, z, and w elements from the first four words of a float array.
// 
// 
inline void loadXYZW( Quat & quat, const float * fptr );

// Store x, y, z, and w elements of a quaternion in the first four words of a float array.
// Memory area of previous 16 bytes and next 32 bytes from fptr might be accessed
// 
inline void storeXYZW( Quat quat, float * fptr );

// Conditionally select between two quaternions
// NOTE: 
// This function uses a conditional select instruction to avoid a branch.
// However, the transfer of select1 to a VMX register may use more processing time than a branch.
// Use the boolInVec version for better performance.
// 
inline const Quat select( Quat quat0, Quat quat1, bool select1 );

// Conditionally select between two quaternions (scalar data contained in vector data type)
// NOTE: 
// This function uses a conditional select instruction to avoid a branch.
// 
inline const Quat select( Quat quat0, Quat quat1, boolInVec select1 );

#ifdef _VECTORMATH_DEBUG

// Print a quaternion
// NOTE: 
// Function is only defined when _VECTORMATH_DEBUG is defined.
// 
inline void print( Quat quat );

// Print a quaternion and an associated string identifier
// NOTE: 
// Function is only defined when _VECTORMATH_DEBUG is defined.
// 
inline void print( Quat quat, const char * name );

#endif

// A 3x3 matrix in array-of-structures format
//
class Matrix3
{
    Vector3 mCol0;
    Vector3 mCol1;
    Vector3 mCol2;

public:
    // Default constructor; does no initialization
    // 
    inline Matrix3( ) { };

    // Copy a 3x3 matrix
    // 
    inline Matrix3( const Matrix3 & mat );

    // Construct a 3x3 matrix containing the specified columns
    // 
    inline Matrix3( Vector3 col0, Vector3 col1, Vector3 col2 );

    // Construct a 3x3 rotation matrix from a unit-length quaternion
    // 
    explicit inline Matrix3( Quat unitQuat );

    // Set all elements of a 3x3 matrix to the same scalar value
    // 
    explicit inline Matrix3( float scalar );

    // Set all elements of a 3x3 matrix to the same scalar value (scalar data contained in vector data type)
    // 
    explicit inline Matrix3( floatInVec scalar );

    // Assign one 3x3 matrix to another
    // 
    inline Matrix3 & operator =( const Matrix3 & mat );

    // Set column 0 of a 3x3 matrix
    // 
    inline Matrix3 & setCol0( Vector3 col0 );

    // Set column 1 of a 3x3 matrix
    // 
    inline Matrix3 & setCol1( Vector3 col1 );

    // Set column 2 of a 3x3 matrix
    // 
    inline Matrix3 & setCol2( Vector3 col2 );

    // Get column 0 of a 3x3 matrix
    // 
    inline const Vector3 getCol0( ) const;

    // Get column 1 of a 3x3 matrix
    // 
    inline const Vector3 getCol1( ) const;

    // Get column 2 of a 3x3 matrix
    // 
    inline const Vector3 getCol2( ) const;

    // Set the column of a 3x3 matrix referred to by the specified index
    // 
    inline Matrix3 & setCol( int col, Vector3 vec );

    // Set the row of a 3x3 matrix referred to by the specified index
    // 
    inline Matrix3 & setRow( int row, Vector3 vec );

    // Get the column of a 3x3 matrix referred to by the specified index
    // 
    inline const Vector3 getCol( int col ) const;

    // Get the row of a 3x3 matrix referred to by the specified index
    // 
    inline const Vector3 getRow( int row ) const;

    // Subscripting operator to set or get a column
    // 
    inline Vector3 & operator []( int col );

    // Subscripting operator to get a column
    // 
    inline const Vector3 operator []( int col ) const;

    // Set the element of a 3x3 matrix referred to by column and row indices
    // 
    inline Matrix3 & setElem( int col, int row, float val );

    // Set the element of a 3x3 matrix referred to by column and row indices (scalar data contained in vector data type)
    // 
    inline Matrix3 & setElem( int col, int row, floatInVec val );

    // Get the element of a 3x3 matrix referred to by column and row indices
    // 
    inline const floatInVec getElem( int col, int row ) const;

    // Add two 3x3 matrices
    // 
    inline const Matrix3 operator +( const Matrix3 & mat ) const;

    // Subtract a 3x3 matrix from another 3x3 matrix
    // 
    inline const Matrix3 operator -( const Matrix3 & mat ) const;

    // Negate all elements of a 3x3 matrix
    // 
    inline const Matrix3 operator -( ) const;

    // Multiply a 3x3 matrix by a scalar
    // 
    inline const Matrix3 operator *( float scalar ) const;

    // Multiply a 3x3 matrix by a scalar (scalar data contained in vector data type)
    // 
    inline const Matrix3 operator *( floatInVec scalar ) const;

    // Multiply a 3x3 matrix by a 3-D vector
    // 
    inline const Vector3 operator *( Vector3 vec ) const;

    // Multiply two 3x3 matrices
    // 
    inline const Matrix3 operator *( const Matrix3 & mat ) const;

    // Perform compound assignment and addition with a 3x3 matrix
    // 
    inline Matrix3 & operator +=( const Matrix3 & mat );

    // Perform compound assignment and subtraction by a 3x3 matrix
    // 
    inline Matrix3 & operator -=( const Matrix3 & mat );

    // Perform compound assignment and multiplication by a scalar
    // 
    inline Matrix3 & operator *=( float scalar );

    // Perform compound assignment and multiplication by a scalar (scalar data contained in vector data type)
    // 
    inline Matrix3 & operator *=( floatInVec scalar );

    // Perform compound assignment and multiplication by a 3x3 matrix
    // 
    inline Matrix3 & operator *=( const Matrix3 & mat );

    // Construct an identity 3x3 matrix
    // 
    static inline const Matrix3 identity( );

    // Construct a 3x3 matrix to rotate around the x axis
    // 
    static inline const Matrix3 rotationX( float radians );

    // Construct a 3x3 matrix to rotate around the y axis
    // 
    static inline const Matrix3 rotationY( float radians );

    // Construct a 3x3 matrix to rotate around the z axis
    // 
    static inline const Matrix3 rotationZ( float radians );

    // Construct a 3x3 matrix to rotate around the x axis (scalar data contained in vector data type)
    // 
    static inline const Matrix3 rotationX( floatInVec radians );

    // Construct a 3x3 matrix to rotate around the y axis (scalar data contained in vector data type)
    // 
    static inline const Matrix3 rotationY( floatInVec radians );

    // Construct a 3x3 matrix to rotate around the z axis (scalar data contained in vector data type)
    // 
    static inline const Matrix3 rotationZ( floatInVec radians );

    // Construct a 3x3 matrix to rotate around the x, y, and z axes
    // 
    static inline const Matrix3 rotationZYX( Vector3 radiansXYZ );

    // Construct a 3x3 matrix to rotate around a unit-length 3-D vector
    // 
    static inline const Matrix3 rotation( float radians, Vector3 unitVec );

    // Construct a 3x3 matrix to rotate around a unit-length 3-D vector (scalar data contained in vector data type)
    // 
    static inline const Matrix3 rotation( floatInVec radians, Vector3 unitVec );

    // Construct a rotation matrix from a unit-length quaternion
    // 
    static inline const Matrix3 rotation( Quat unitQuat );

    // Construct a 3x3 matrix to perform scaling
    // 
    static inline const Matrix3 scale( Vector3 scaleVec );

};
// Multiply a 3x3 matrix by a scalar
// 
inline const Matrix3 operator *( float scalar, const Matrix3 & mat );

// Multiply a 3x3 matrix by a scalar (scalar data contained in vector data type)
// 
inline const Matrix3 operator *( floatInVec scalar, const Matrix3 & mat );

// Append (post-multiply) a scale transformation to a 3x3 matrix
// NOTE: 
// Faster than creating and multiplying a scale transformation matrix.
// 
inline const Matrix3 appendScale( const Matrix3 & mat, Vector3 scaleVec );

// Prepend (pre-multiply) a scale transformation to a 3x3 matrix
// NOTE: 
// Faster than creating and multiplying a scale transformation matrix.
// 
inline const Matrix3 prependScale( Vector3 scaleVec, const Matrix3 & mat );

// Multiply two 3x3 matrices per element
// 
inline const Matrix3 mulPerElem( const Matrix3 & mat0, const Matrix3 & mat1 );

// Compute the absolute value of a 3x3 matrix per element
// 
inline const Matrix3 absPerElem( const Matrix3 & mat );

// Transpose of a 3x3 matrix
// 
inline const Matrix3 transpose( const Matrix3 & mat );

// Compute the inverse of a 3x3 matrix
// NOTE: 
// Result is unpredictable when the determinant of mat is equal to or near 0.
// 
inline const Matrix3 inverse( const Matrix3 & mat );

// Determinant of a 3x3 matrix
// 
inline const floatInVec determinant( const Matrix3 & mat );

// Conditionally select between two 3x3 matrices
// NOTE: 
// This function uses a conditional select instruction to avoid a branch.
// However, the transfer of select1 to a VMX register may use more processing time than a branch.
// Use the boolInVec version for better performance.
// 
inline const Matrix3 select( const Matrix3 & mat0, const Matrix3 & mat1, bool select1 );

// Conditionally select between two 3x3 matrices (scalar data contained in vector data type)
// NOTE: 
// This function uses a conditional select instruction to avoid a branch.
// 
inline const Matrix3 select( const Matrix3 & mat0, const Matrix3 & mat1, boolInVec select1 );

#ifdef _VECTORMATH_DEBUG

// Print a 3x3 matrix
// NOTE: 
// Function is only defined when _VECTORMATH_DEBUG is defined.
// 
inline void print( const Matrix3 & mat );

// Print a 3x3 matrix and an associated string identifier
// NOTE: 
// Function is only defined when _VECTORMATH_DEBUG is defined.
// 
inline void print( const Matrix3 & mat, const char * name );

#endif

// A 4x4 matrix in array-of-structures format
//
class Matrix4
{
    Vector4 mCol0;
    Vector4 mCol1;
    Vector4 mCol2;
    Vector4 mCol3;

public:
    // Default constructor; does no initialization
    // 
    inline Matrix4( ) { };

    // Copy a 4x4 matrix
    // 
    inline Matrix4( const Matrix4 & mat );

    // Construct a 4x4 matrix containing the specified columns
    // 
    inline Matrix4( Vector4 col0, Vector4 col1, Vector4 col2, Vector4 col3 );

    // Construct a 4x4 matrix from a 3x4 transformation matrix
    // 
    explicit inline Matrix4( const Transform3 & mat );

    // Construct a 4x4 matrix from a 3x3 matrix and a 3-D vector
    // 
    inline Matrix4( const Matrix3 & mat, Vector3 translateVec );

    // Construct a 4x4 matrix from a unit-length quaternion and a 3-D vector
    // 
    inline Matrix4( Quat unitQuat, Vector3 translateVec );

    // Set all elements of a 4x4 matrix to the same scalar value
    // 
    explicit inline Matrix4( float scalar );

    // Set all elements of a 4x4 matrix to the same scalar value (scalar data contained in vector data type)
    // 
    explicit inline Matrix4( floatInVec scalar );

    // Assign one 4x4 matrix to another
    // 
    inline Matrix4 & operator =( const Matrix4 & mat );

    // Set the upper-left 3x3 submatrix
    // NOTE: 
    // This function does not change the bottom row elements.
    // 
    inline Matrix4 & setUpper3x3( const Matrix3 & mat3 );

    // Get the upper-left 3x3 submatrix of a 4x4 matrix
    // 
    inline const Matrix3 getUpper3x3( ) const;

    // Set translation component
    // NOTE: 
    // This function does not change the bottom row elements.
    // 
    inline Matrix4 & setTranslation( Vector3 translateVec );

    // Get the translation component of a 4x4 matrix
    // 
    inline const Vector3 getTranslation( ) const;

    // Set column 0 of a 4x4 matrix
    // 
    inline Matrix4 & setCol0( Vector4 col0 );

    // Set column 1 of a 4x4 matrix
    // 
    inline Matrix4 & setCol1( Vector4 col1 );

    // Set column 2 of a 4x4 matrix
    // 
    inline Matrix4 & setCol2( Vector4 col2 );

    // Set column 3 of a 4x4 matrix
    // 
    inline Matrix4 & setCol3( Vector4 col3 );

    // Get column 0 of a 4x4 matrix
    // 
    inline const Vector4 getCol0( ) const;

    // Get column 1 of a 4x4 matrix
    // 
    inline const Vector4 getCol1( ) const;

    // Get column 2 of a 4x4 matrix
    // 
    inline const Vector4 getCol2( ) const;

    // Get column 3 of a 4x4 matrix
    // 
    inline const Vector4 getCol3( ) const;

    // Set the column of a 4x4 matrix referred to by the specified index
    // 
    inline Matrix4 & setCol( int col, Vector4 vec );

    // Set the row of a 4x4 matrix referred to by the specified index
    // 
    inline Matrix4 & setRow( int row, Vector4 vec );

    // Get the column of a 4x4 matrix referred to by the specified index
    // 
    inline const Vector4 getCol( int col ) const;

    // Get the row of a 4x4 matrix referred to by the specified index
    // 
    inline const Vector4 getRow( int row ) const;

    // Subscripting operator to set or get a column
    // 
    inline Vector4 & operator []( int col );

    // Subscripting operator to get a column
    // 
    inline const Vector4 operator []( int col ) const;

    // Set the element of a 4x4 matrix referred to by column and row indices
    // 
    inline Matrix4 & setElem( int col, int row, float val );

    // Set the element of a 4x4 matrix referred to by column and row indices (scalar data contained in vector data type)
    // 
    inline Matrix4 & setElem( int col, int row, floatInVec val );

    // Get the element of a 4x4 matrix referred to by column and row indices
    // 
    inline const floatInVec getElem( int col, int row ) const;

    // Add two 4x4 matrices
    // 
    inline const Matrix4 operator +( const Matrix4 & mat ) const;

    // Subtract a 4x4 matrix from another 4x4 matrix
    // 
    inline const Matrix4 operator -( const Matrix4 & mat ) const;

    // Negate all elements of a 4x4 matrix
    // 
    inline const Matrix4 operator -( ) const;

    // Multiply a 4x4 matrix by a scalar
    // 
    inline const Matrix4 operator *( float scalar ) const;

    // Multiply a 4x4 matrix by a scalar (scalar data contained in vector data type)
    // 
    inline const Matrix4 operator *( floatInVec scalar ) const;

    // Multiply a 4x4 matrix by a 4-D vector
    // 
    inline const Vector4 operator *( Vector4 vec ) const;

    // Multiply a 4x4 matrix by a 3-D vector
    // 
    inline const Vector4 operator *( Vector3 vec ) const;

    // Multiply a 4x4 matrix by a 3-D point
    // 
    inline const Vector4 operator *( Point3 pnt ) const;

    // Multiply two 4x4 matrices
    // 
    inline const Matrix4 operator *( const Matrix4 & mat ) const;

    // Multiply a 4x4 matrix by a 3x4 transformation matrix
    // 
    inline const Matrix4 operator *( const Transform3 & tfrm ) const;

    // Perform compound assignment and addition with a 4x4 matrix
    // 
    inline Matrix4 & operator +=( const Matrix4 & mat );

    // Perform compound assignment and subtraction by a 4x4 matrix
    // 
    inline Matrix4 & operator -=( const Matrix4 & mat );

    // Perform compound assignment and multiplication by a scalar
    // 
    inline Matrix4 & operator *=( float scalar );

    // Perform compound assignment and multiplication by a scalar (scalar data contained in vector data type)
    // 
    inline Matrix4 & operator *=( floatInVec scalar );

    // Perform compound assignment and multiplication by a 4x4 matrix
    // 
    inline Matrix4 & operator *=( const Matrix4 & mat );

    // Perform compound assignment and multiplication by a 3x4 transformation matrix
    // 
    inline Matrix4 & operator *=( const Transform3 & tfrm );

	inline bool operator == (const Matrix4& mat) const;
	
	inline bool operator != (const Matrix4& mat) const;
	
    // Construct an identity 4x4 matrix
    // 
    static inline const Matrix4 identity( );

    // Construct a 4x4 matrix to rotate around the x axis
    // 
    static inline const Matrix4 rotationX( float radians );

    // Construct a 4x4 matrix to rotate around the y axis
    // 
    static inline const Matrix4 rotationY( float radians );

    // Construct a 4x4 matrix to rotate around the z axis
    // 
    static inline const Matrix4 rotationZ( float radians );

    // Construct a 4x4 matrix to rotate around the x axis (scalar data contained in vector data type)
    // 
    static inline const Matrix4 rotationX( floatInVec radians );

    // Construct a 4x4 matrix to rotate around the y axis (scalar data contained in vector data type)
    // 
    static inline const Matrix4 rotationY( floatInVec radians );

    // Construct a 4x4 matrix to rotate around the z axis (scalar data contained in vector data type)
    // 
    static inline const Matrix4 rotationZ( floatInVec radians );

    // Construct a 4x4 matrix to rotate around the x, y, and z axes
    // 
    static inline const Matrix4 rotationZYX( Vector3 radiansXYZ );

    // Construct a 4x4 matrix to rotate around a unit-length 3-D vector
    // 
    static inline const Matrix4 rotation( float radians, Vector3 unitVec );

    // Construct a 4x4 matrix to rotate around a unit-length 3-D vector (scalar data contained in vector data type)
    // 
    static inline const Matrix4 rotation( floatInVec radians, Vector3 unitVec );

    // Construct a rotation matrix from a unit-length quaternion
    // 
    static inline const Matrix4 rotation( Quat unitQuat );

    // Construct a 4x4 matrix to perform scaling
    // 
    static inline const Matrix4 scale( Vector3 scaleVec );

    // Construct a 4x4 matrix to perform translation
    // 
    static inline const Matrix4 translation( Vector3 translateVec );

    // Construct viewing matrix based on eye position, position looked at, and up direction
    // 
    static inline const Matrix4 lookAt( Point3 eyePos, Point3 lookAtPos, Vector3 upVec );

    // Construct a perspective projection matrix
    // 
    static inline const Matrix4 perspective( float fovyRadians, float aspect, float zNear, float zFar );

    // Construct a perspective projection matrix based on frustum
    // 
    static inline const Matrix4 frustum( float left, float right, float bottom, float top, float zNear, float zFar );

    // Construct an orthographic projection matrix
    // 
    static inline const Matrix4 orthographic( float left, float right, float bottom, float top, float zNear, float zFar );

};
// Multiply a 4x4 matrix by a scalar
// 
inline const Matrix4 operator *( float scalar, const Matrix4 & mat );

// Multiply a 4x4 matrix by a scalar (scalar data contained in vector data type)
// 
inline const Matrix4 operator *( floatInVec scalar, const Matrix4 & mat );

// Append (post-multiply) a scale transformation to a 4x4 matrix
// NOTE: 
// Faster than creating and multiplying a scale transformation matrix.
// 
inline const Matrix4 appendScale( const Matrix4 & mat, Vector3 scaleVec );

// Prepend (pre-multiply) a scale transformation to a 4x4 matrix
// NOTE: 
// Faster than creating and multiplying a scale transformation matrix.
// 
inline const Matrix4 prependScale( Vector3 scaleVec, const Matrix4 & mat );

// Multiply two 4x4 matrices per element
// 
inline const Matrix4 mulPerElem( const Matrix4 & mat0, const Matrix4 & mat1 );

// Compute the absolute value of a 4x4 matrix per element
// 
inline const Matrix4 absPerElem( const Matrix4 & mat );

// Transpose of a 4x4 matrix
// 
inline const Matrix4 transpose( const Matrix4 & mat );

// Compute the inverse of a 4x4 matrix
// NOTE: 
// Result is unpredictable when the determinant of mat is equal to or near 0.
// 
inline const Matrix4 inverse( const Matrix4 & mat );

// Compute the inverse of a 4x4 matrix, which is expected to be an affine matrix
// NOTE: 
// This can be used to achieve better performance than a general inverse when the specified 4x4 matrix meets the given restrictions.  The result is unpredictable when the determinant of mat is equal to or near 0.
// 
inline const Matrix4 affineInverse( const Matrix4 & mat );

// Compute the inverse of a 4x4 matrix, which is expected to be an affine matrix with an orthogonal upper-left 3x3 submatrix
// NOTE: 
// This can be used to achieve better performance than a general inverse when the specified 4x4 matrix meets the given restrictions.
// 
inline const Matrix4 orthoInverse( const Matrix4 & mat );

// Determinant of a 4x4 matrix
// 
inline const floatInVec determinant( const Matrix4 & mat );

// Conditionally select between two 4x4 matrices
// NOTE: 
// This function uses a conditional select instruction to avoid a branch.
// However, the transfer of select1 to a VMX register may use more processing time than a branch.
// Use the boolInVec version for better performance.
// 
inline const Matrix4 select( const Matrix4 & mat0, const Matrix4 & mat1, bool select1 );

// Conditionally select between two 4x4 matrices (scalar data contained in vector data type)
// NOTE: 
// This function uses a conditional select instruction to avoid a branch.
// 
inline const Matrix4 select( const Matrix4 & mat0, const Matrix4 & mat1, boolInVec select1 );

#ifdef _VECTORMATH_DEBUG

// Print a 4x4 matrix
// NOTE: 
// Function is only defined when _VECTORMATH_DEBUG is defined.
// 
inline void print( const Matrix4 & mat );

// Print a 4x4 matrix and an associated string identifier
// NOTE: 
// Function is only defined when _VECTORMATH_DEBUG is defined.
// 
inline void print( const Matrix4 & mat, const char * name );

#endif

// A 3x4 transformation matrix in array-of-structures format
//
class Transform3
{
    Vector3 mCol0;
    Vector3 mCol1;
    Vector3 mCol2;
    Vector3 mCol3;

public:
    // Default constructor; does no initialization
    // 
    inline Transform3( ) { };

    // Copy a 3x4 transformation matrix
    // 
    inline Transform3( const Transform3 & tfrm );

    // Construct a 3x4 transformation matrix containing the specified columns
    // 
    inline Transform3( Vector3 col0, Vector3 col1, Vector3 col2, Vector3 col3 );

    // Construct a 3x4 transformation matrix from a 3x3 matrix and a 3-D vector
    // 
    inline Transform3( const Matrix3 & tfrm, Vector3 translateVec );

    // Construct a 3x4 transformation matrix from a unit-length quaternion and a 3-D vector
    // 
    inline Transform3( Quat unitQuat, Vector3 translateVec );

    // Set all elements of a 3x4 transformation matrix to the same scalar value
    // 
    explicit inline Transform3( float scalar );

    // Set all elements of a 3x4 transformation matrix to the same scalar value (scalar data contained in vector data type)
    // 
    explicit inline Transform3( floatInVec scalar );

    // Assign one 3x4 transformation matrix to another
    // 
    inline Transform3 & operator =( const Transform3 & tfrm );

    // Set the upper-left 3x3 submatrix
    // 
    inline Transform3 & setUpper3x3( const Matrix3 & mat3 );

    // Get the upper-left 3x3 submatrix of a 3x4 transformation matrix
    // 
    inline const Matrix3 getUpper3x3( ) const;

    // Set translation component
    // 
    inline Transform3 & setTranslation( Vector3 translateVec );

    // Get the translation component of a 3x4 transformation matrix
    // 
    inline const Vector3 getTranslation( ) const;

    // Set column 0 of a 3x4 transformation matrix
    // 
    inline Transform3 & setCol0( Vector3 col0 );

    // Set column 1 of a 3x4 transformation matrix
    // 
    inline Transform3 & setCol1( Vector3 col1 );

    // Set column 2 of a 3x4 transformation matrix
    // 
    inline Transform3 & setCol2( Vector3 col2 );

    // Set column 3 of a 3x4 transformation matrix
    // 
    inline Transform3 & setCol3( Vector3 col3 );

    // Get column 0 of a 3x4 transformation matrix
    // 
    inline const Vector3 getCol0( ) const;

    // Get column 1 of a 3x4 transformation matrix
    // 
    inline const Vector3 getCol1( ) const;

    // Get column 2 of a 3x4 transformation matrix
    // 
    inline const Vector3 getCol2( ) const;

    // Get column 3 of a 3x4 transformation matrix
    // 
    inline const Vector3 getCol3( ) const;

    // Set the column of a 3x4 transformation matrix referred to by the specified index
    // 
    inline Transform3 & setCol( int col, Vector3 vec );

    // Set the row of a 3x4 transformation matrix referred to by the specified index
    // 
    inline Transform3 & setRow( int row, Vector4 vec );

    // Get the column of a 3x4 transformation matrix referred to by the specified index
    // 
    inline const Vector3 getCol( int col ) const;

    // Get the row of a 3x4 transformation matrix referred to by the specified index
    // 
    inline const Vector4 getRow( int row ) const;

    // Subscripting operator to set or get a column
    // 
    inline Vector3 & operator []( int col );

    // Subscripting operator to get a column
    // 
    inline const Vector3 operator []( int col ) const;

    // Set the element of a 3x4 transformation matrix referred to by column and row indices
    // 
    inline Transform3 & setElem( int col, int row, float val );

    // Set the element of a 3x4 transformation matrix referred to by column and row indices (scalar data contained in vector data type)
    // 
    inline Transform3 & setElem( int col, int row, floatInVec val );

    // Get the element of a 3x4 transformation matrix referred to by column and row indices
    // 
    inline const floatInVec getElem( int col, int row ) const;

    // Multiply a 3x4 transformation matrix by a 3-D vector
    // 
    inline const Vector3 operator *( Vector3 vec ) const;

    // Multiply a 3x4 transformation matrix by a 3-D point
    // 
    inline const Point3 operator *( Point3 pnt ) const;

    // Multiply two 3x4 transformation matrices
    // 
    inline const Transform3 operator *( const Transform3 & tfrm ) const;

    // Perform compound assignment and multiplication by a 3x4 transformation matrix
    // 
    inline Transform3 & operator *=( const Transform3 & tfrm );

    // Construct an identity 3x4 transformation matrix
    // 
    static inline const Transform3 identity( );

    // Construct a 3x4 transformation matrix to rotate around the x axis
    // 
    static inline const Transform3 rotationX( float radians );

    // Construct a 3x4 transformation matrix to rotate around the y axis
    // 
    static inline const Transform3 rotationY( float radians );

    // Construct a 3x4 transformation matrix to rotate around the z axis
    // 
    static inline const Transform3 rotationZ( float radians );

    // Construct a 3x4 transformation matrix to rotate around the x axis (scalar data contained in vector data type)
    // 
    static inline const Transform3 rotationX( floatInVec radians );

    // Construct a 3x4 transformation matrix to rotate around the y axis (scalar data contained in vector data type)
    // 
    static inline const Transform3 rotationY( floatInVec radians );

    // Construct a 3x4 transformation matrix to rotate around the z axis (scalar data contained in vector data type)
    // 
    static inline const Transform3 rotationZ( floatInVec radians );

    // Construct a 3x4 transformation matrix to rotate around the x, y, and z axes
    // 
    static inline const Transform3 rotationZYX( Vector3 radiansXYZ );

    // Construct a 3x4 transformation matrix to rotate around a unit-length 3-D vector
    // 
    static inline const Transform3 rotation( float radians, Vector3 unitVec );

    // Construct a 3x4 transformation matrix to rotate around a unit-length 3-D vector (scalar data contained in vector data type)
    // 
    static inline const Transform3 rotation( floatInVec radians, Vector3 unitVec );

    // Construct a rotation matrix from a unit-length quaternion
    // 
    static inline const Transform3 rotation( Quat unitQuat );

    // Construct a 3x4 transformation matrix to perform scaling
    // 
    static inline const Transform3 scale( Vector3 scaleVec );

    // Construct a 3x4 transformation matrix to perform translation
    // 
    static inline const Transform3 translation( Vector3 translateVec );

};
// Append (post-multiply) a scale transformation to a 3x4 transformation matrix
// NOTE: 
// Faster than creating and multiplying a scale transformation matrix.
// 
inline const Transform3 appendScale( const Transform3 & tfrm, Vector3 scaleVec );

// Prepend (pre-multiply) a scale transformation to a 3x4 transformation matrix
// NOTE: 
// Faster than creating and multiplying a scale transformation matrix.
// 
inline const Transform3 prependScale( Vector3 scaleVec, const Transform3 & tfrm );

// Multiply two 3x4 transformation matrices per element
// 
inline const Transform3 mulPerElem( const Transform3 & tfrm0, const Transform3 & tfrm1 );

// Compute the absolute value of a 3x4 transformation matrix per element
// 
inline const Transform3 absPerElem( const Transform3 & tfrm );

// Inverse of a 3x4 transformation matrix
// NOTE: 
// Result is unpredictable when the determinant of the left 3x3 submatrix is equal to or near 0.
// 
inline const Transform3 inverse( const Transform3 & tfrm );

// Compute the inverse of a 3x4 transformation matrix, expected to have an orthogonal upper-left 3x3 submatrix
// NOTE: 
// This can be used to achieve better performance than a general inverse when the specified 3x4 transformation matrix meets the given restrictions.
// 
inline const Transform3 orthoInverse( const Transform3 & tfrm );

// Conditionally select between two 3x4 transformation matrices
// NOTE: 
// This function uses a conditional select instruction to avoid a branch.
// However, the transfer of select1 to a VMX register may use more processing time than a branch.
// Use the boolInVec version for better performance.
// 
inline const Transform3 select( const Transform3 & tfrm0, const Transform3 & tfrm1, bool select1 );

// Conditionally select between two 3x4 transformation matrices (scalar data contained in vector data type)
// NOTE: 
// This function uses a conditional select instruction to avoid a branch.
// 
inline const Transform3 select( const Transform3 & tfrm0, const Transform3 & tfrm1, boolInVec select1 );

#ifdef _VECTORMATH_DEBUG

// Print a 3x4 transformation matrix
// NOTE: 
// Function is only defined when _VECTORMATH_DEBUG is defined.
// 
inline void print( const Transform3 & tfrm );

// Print a 3x4 transformation matrix and an associated string identifier
// NOTE: 
// Function is only defined when _VECTORMATH_DEBUG is defined.
// 
inline void print( const Transform3 & tfrm, const char * name );

#endif

} // namespace Aos
} // namespace Vectormath

#include "vec_aos.h"
#include "quat_aos.h"
#include "mat_aos.h"

#endif
