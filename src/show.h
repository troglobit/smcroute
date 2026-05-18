/* Output mode for smcroutectl show subcommands. */
#ifndef SMCROUTE_SHOW_H_
#define SMCROUTE_SHOW_H_

enum show_mode {
	SHOW_BRIEF,	/* default human-readable table */
	SHOW_DETAIL,	/* table with extra columns      */
	SHOW_JSON,	/* JSON object, smcroutectl -j   */
};

#endif /* SMCROUTE_SHOW_H_ */
