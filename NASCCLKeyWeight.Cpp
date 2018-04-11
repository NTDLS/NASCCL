#ifndef _NASCCL_Hash_KeyWeight_Cpp_
#define _NASCCL_Hash_KeyWeight_Cpp_
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <StdIO.H>
#include <Windows.H>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "NASCCL.H"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const char *gsKeyWeights[] = {
	"Unacceptable",
	"Very Weak",
	"Weak",
	"Acceptable",
	"Strong",
	"Very Strong",
	"Excellent",
	NULL
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const char * CNASCCL::KeyWeightString(const char *sKey)
{
	return gsKeyWeights[KeyWeight(sKey)];
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const char * CNASCCL::KeyWeightString(const void *lpKey, int iKeySz)
{
	return gsKeyWeights[KeyWeight(lpKey, iKeySz)];
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int CNASCCL::KeyWeight(const void *lpKey, int iKeySz)
{
	int iV = 0;
	int iNums = 0;
	int iSymbols = 0;
	int iCapChars = 0;
	int iLowChars = 0;
	int iExtChars = 0;
	int iSeg = (iKeySz / 8); //How many 8-character segments is the password comprised of?

	//Figure out how many different types of characters are used in the password.
	for(int iRPos = 0; iRPos < iKeySz; iRPos++)
	{
		iV = ((NByte *)lpKey)[iRPos];

		if(iV>=48 && iV<=57) {
			iNums++;
		}
		else if(iV>=65 && iV<=90) {
			iCapChars++;
		}
		else if(iV>=97 && iV<=121) {
			iLowChars++;
		}
		else if((iV>=32 && iV<=47) || (iV>=58 && iV<=64) || (iV>=91 && iV<=96) || (iV>=123 && iV<=126)) {
			iSymbols++;
		}

		else{
			iExtChars++;
		}
	}

	//The score is based first on the number of 8-character segments in the password.
	//	If the password is comprised of more than 6 of these segments then set the
	//		score to 6, the'll be no extra credit for a really-really long password
	//		as it could simply be a string of 1 million A's.
	if((iV = iSeg) > KW_PERFECT)
	{
		iV = KW_PERFECT;
	}

	//Take one point away from the score for each character type that is not used.
	//Also, we do not take away credit for not using extended characters... but we do give it.
	iV -= ((iSeg == 0) + (iNums==0) + (iSymbols==0) + (iCapChars==0) + (iLowChars==0));

	//We do not allow the score to go below -1 before we start to
	//	credit the score. So if the score is below -1 reset it to -1.
	if(iV < -1)
	{
		iV = -1;
	}

	//Give one point for each character type that is used.
	iV += ((iNums>0) + (iSymbols>0) + (iCapChars>0) + (iLowChars>0) + (iExtChars>0));

	if(iV < KW_UNACCEPTABLE)
	{
		return KW_UNACCEPTABLE;
	}
	else if(iV > KW_PERFECT)
	{
		return KW_PERFECT;
	}
	else{
		return iV;
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int CNASCCL::KeyWeight(const char *sKey)
{
	return KeyWeight(sKey, strlen(sKey));
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif
